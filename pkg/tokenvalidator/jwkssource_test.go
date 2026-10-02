package tokenvalidator

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// jwksTestKey is one entry this file's fake JWKS server publishes.
type jwksTestKey struct {
	kid string
	pub *rsa.PublicKey
}

// buildJWKSBody renders keys as a JWKS document -- the same shape
// internal/keys.Keyset.JWKS produces (kid and alg set on each public JWK),
// reproduced here since pkg/ may not import internal/ (ADR-0001) and this
// package is the one that would be extracted first if it ever is.
func buildJWKSBody(t *testing.T, keys ...jwksTestKey) []byte {
	t.Helper()
	set := jwk.NewSet()
	for _, k := range keys {
		pubJWK, err := jwk.Import[jwk.Key](k.pub)
		if err != nil {
			t.Fatalf("jwk.Import: %v", err)
		}
		if err := pubJWK.Set(jwk.KeyIDKey, k.kid); err != nil {
			t.Fatalf("set kid: %v", err)
		}
		if err := pubJWK.Set(jwk.AlgorithmKey, "RS256"); err != nil {
			t.Fatalf("set alg: %v", err)
		}
		if err := set.AddKey(pubJWK); err != nil {
			t.Fatalf("AddKey: %v", err)
		}
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return body
}

// jwksTestServer is a fake AS's /.well-known/jwks.json: swappable body
// (simulating a newly published key appearing) and a request counter
// (this file's own "counting fake" for the burst-fetch done-when).
type jwksTestServer struct {
	*httptest.Server
	hits *atomic.Int64

	mu   sync.Mutex
	body []byte
}

func newJWKSTestServer(t *testing.T, initial ...jwksTestKey) *jwksTestServer {
	t.Helper()
	s := &jwksTestServer{hits: &atomic.Int64{}, body: buildJWKSBody(t, initial...)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		body := s.body
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksTestServer) setKeys(t *testing.T, keys ...jwksTestKey) {
	t.Helper()
	s.mu.Lock()
	s.body = buildJWKSBody(t, keys...)
	s.mu.Unlock()
}

func testRSAPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return &priv.PublicKey
}

func TestJWKSSource_GoldenPath(t *testing.T) {
	pub := testRSAPublicKey(t)
	server := newJWKSTestServer(t, jwksTestKey{kid: "key-1", pub: pub})
	source := NewJWKSSource(server.URL, server.Client(), 5, time.Minute)

	gotPub, alg, err := source.Key(t.Context(), "key-1")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if alg != RS256 {
		t.Errorf("alg = %q, want %q", alg, RS256)
	}
	gotRSA, ok := gotPub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("resolved key is a %T, want *rsa.PublicKey", gotPub)
	}
	if gotRSA.N.Cmp(pub.N) != 0 {
		t.Error("resolved public key does not match the one the server published")
	}
}

func TestJWKSSource_UnknownKIDAfterFetchReturnsErrUnknownKID(t *testing.T) {
	server := newJWKSTestServer(t, jwksTestKey{kid: "key-1", pub: testRSAPublicKey(t)})
	source := NewJWKSSource(server.URL, server.Client(), 5, time.Minute)

	if _, _, err := source.Key(t.Context(), "never-existed"); !errors.Is(err, ErrUnknownKID) {
		t.Errorf("Key(never-existed) = %v, want ErrUnknownKID", err)
	}
}

// TestJWKSSource_BurstOfUnknownKIDsCausesAtMostConfiguredFetches is the
// issue's own first done-when: a burst of lookups for distinct,
// never-valid kid values must not cause more than refetchLimit outbound
// fetches, counted by this file's own fake server (the "counting fake").
//
// Negative control: with the `s.limiter.Allow(ctx, refetchLimiterKey)`
// check in Key replaced with an unconditional `true`, this test failed --
// the fake server recorded a fetch for every one of the 50 concurrent
// lookups, 10x the configured limit. Verified by hand, restored before
// committing.
func TestJWKSSource_BurstOfUnknownKIDsCausesAtMostConfiguredFetches(t *testing.T) {
	server := newJWKSTestServer(t, jwksTestKey{kid: "key-1", pub: testRSAPublicKey(t)})
	const refetchLimit = 5
	source := NewJWKSSource(server.URL, server.Client(), refetchLimit, time.Minute)

	const burst = 50
	var wg sync.WaitGroup
	wg.Add(burst)
	for i := range burst {
		go func(i int) {
			defer wg.Done()
			_, _, _ = source.Key(t.Context(), fmt.Sprintf("never-existed-%d", i))
		}(i)
	}
	wg.Wait()

	if got := server.hits.Load(); got > refetchLimit {
		t.Errorf("fake server received %d requests for a burst of %d unknown kids, want at most %d", got, burst, refetchLimit)
	}
}

// TestJWKSSource_NewlyPublishedKeyPickedUpWithoutRestart is the issue's
// own second done-when: the same JWKSSource instance, no reconstruction,
// notices a key that did not exist at its last fetch once the AS
// publishes it.
//
// Negative control: with a `seen map[string]bool` added to JWKSSource,
// marking a kid as permanently not-found on its first miss and having
// Key return ErrUnknownKID immediately for any kid in that set without
// ever fetching again, this test failed -- the second Key call for
// "key-2" returned ErrUnknownKID without the fake server recording a
// second request at all. Verified by hand, reverted before committing.
func TestJWKSSource_NewlyPublishedKeyPickedUpWithoutRestart(t *testing.T) {
	server := newJWKSTestServer(t, jwksTestKey{kid: "key-1", pub: testRSAPublicKey(t)})
	source := NewJWKSSource(server.URL, server.Client(), 5, time.Minute)

	if _, _, err := source.Key(t.Context(), "key-2"); !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("Key(key-2) before publication = %v, want ErrUnknownKID", err)
	}

	newPub := testRSAPublicKey(t)
	server.setKeys(t, jwksTestKey{kid: "key-1", pub: testRSAPublicKey(t)}, jwksTestKey{kid: "key-2", pub: newPub})

	gotPub, _, err := source.Key(t.Context(), "key-2")
	if err != nil {
		t.Fatalf("Key(key-2) after publication: %v", err)
	}
	gotRSA, ok := gotPub.(*rsa.PublicKey)
	if !ok || gotRSA.N.Cmp(newPub.N) != 0 {
		t.Error("Key(key-2) after publication did not return the newly published key")
	}
}

func TestJWKSSource_CachedKIDNeverRefetches(t *testing.T) {
	server := newJWKSTestServer(t, jwksTestKey{kid: "key-1", pub: testRSAPublicKey(t)})
	source := NewJWKSSource(server.URL, server.Client(), 1, time.Minute)

	if _, _, err := source.Key(t.Context(), "key-1"); err != nil {
		t.Fatalf("first Key(key-1): %v", err)
	}
	hitsAfterFirst := server.hits.Load()

	for range 10 {
		if _, _, err := source.Key(t.Context(), "key-1"); err != nil {
			t.Fatalf("repeat Key(key-1): %v", err)
		}
	}

	if got := server.hits.Load(); got != hitsAfterFirst {
		t.Errorf("fake server received %d more requests for 10 repeat lookups of an already-cached kid, want 0 more", got-hitsAfterFirst)
	}
}
