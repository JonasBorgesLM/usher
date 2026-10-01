package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

// Real RSA/ECDSA key generation is the point -- REQUIREMENTS §10 forbids a
// fake here the same way it forbids one for redisstore or Postgres: the
// property under test is how a real crypto.Signer and a real PKCS8 PEM
// round-trip, which a stand-in cannot reproduce by construction. Generated
// once and shared read-only across tests, since the crypto material itself
// does not need to be unique between unrelated tests, only the kid label
// does.
var (
	testRSAOnce sync.Once
	testRSAKey  *rsa.PrivateKey
	testECOnce  sync.Once
	testECKey   *ecdsa.PrivateKey
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAOnce.Do(func() {
		var err error
		testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
	})
	return testRSAKey
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	testECOnce.Do(func() {
		var err error
		testECKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ECDSA key: %v", err)
		}
	})
	return testECKey
}

// writeKeyFile writes "<kid>.json" + "<kid>.pem" into dir, the on-disk
// shape Load reads.
func writeKeyFile(t *testing.T, dir, kid, algorithm string, signer crypto.Signer, publishAt, signFrom, retireAt time.Time) {
	t.Helper()

	meta := keyMetadata{KID: kid, Algorithm: algorithm, PublishAt: publishAt, SignFrom: signFrom, RetireAt: retireAt}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if writeErr := os.WriteFile(filepath.Join(dir, kid+".json"), metaBytes, 0o600); writeErr != nil {
		t.Fatalf("write metadata: %v", writeErr)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if writeErr := os.WriteFile(filepath.Join(dir, kid+".pem"), pemBytes, 0o600); writeErr != nil {
		t.Fatalf("write PEM: %v", writeErr)
	}
}

// Generous defaults: a 10-minute consumer JWKS cache, a 5-minute access
// token TTL, a 30-second clock skew allowance -- chosen so a single key's
// publish_at an hour before sign_from, and a far-future retire_at, satisfy
// every window check by default; individual tests narrow a window on
// purpose to violate exactly one check.
const (
	testClockSkew            = 30 * time.Second
	testMaxAccessTokenTTL    = 5 * time.Minute
	testConsumerJWKSCacheTTL = 10 * time.Minute
)

func TestLoad_ValidSingleKey(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	writeKeyFile(t, dir, "key-1", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))

	ks, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	key, err := ks.Signing(now)
	if err != nil {
		t.Fatalf("Signing: %v", err)
	}
	if key.KID != "key-1" {
		t.Errorf("Signing returned kid %q, want %q", key.KID, "key-1")
	}
}

func TestLoad_MissingDirectoryRefuses(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist"), testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil)
	if err == nil {
		t.Fatal("Load against a missing directory succeeded, want an error")
	}
}

func TestLoad_EmptyDirectoryRefuses(t *testing.T) {
	_, err := Load(t.TempDir(), testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil)
	if err == nil {
		t.Fatal("Load against an empty directory succeeded, want an error")
	}
}

func TestLoad_MalformedJSONRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key-1.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write malformed metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key-1.pem"), []byte("irrelevant"), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	if _, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil); err == nil {
		t.Fatal("Load against malformed JSON metadata succeeded, want an error")
	}
}

func TestLoad_MissingPEMFileRefuses(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	meta := keyMetadata{KID: "key-1", Algorithm: string(tokenvalidator.RS256), PublishAt: now.Add(-time.Hour), SignFrom: now, RetireAt: now.AddDate(1, 0, 0)}
	metaBytes, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(dir, "key-1.json"), metaBytes, 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	// Deliberately no key-1.pem.
	if _, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil); err == nil {
		t.Fatal("Load with no .pem file succeeded, want an error")
	}
}

func TestLoad_AlgorithmKeyTypeMismatchRefuses(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// Claims RS256 in metadata, but the file holds an ECDSA key.
	writeKeyFile(t, dir, "key-1", string(tokenvalidator.RS256), ecKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))

	if _, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil); err == nil {
		t.Fatal("Load with an RS256 metadata entry over an ECDSA key succeeded, want an error")
	}
}

func TestLoad_KIDMismatchBetweenFilenameAndMetadataRefuses(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeKeyFile(t, dir, "key-1", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))
	// Rename the pair so the filename says "key-2" but the JSON still says "key-1".
	if err := os.Rename(filepath.Join(dir, "key-1.json"), filepath.Join(dir, "key-2.json")); err != nil {
		t.Fatalf("rename metadata: %v", err)
	}
	if err := os.Rename(filepath.Join(dir, "key-1.pem"), filepath.Join(dir, "key-2.pem")); err != nil {
		t.Fatalf("rename pem: %v", err)
	}

	if _, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil); err == nil {
		t.Fatal("Load with a filename/metadata kid mismatch succeeded, want an error")
	}
}

func TestLoad_PublishAtAfterSignFromRefuses(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// publish_at is AFTER sign_from: the key would sign before it was ever published.
	writeKeyFile(t, dir, "key-1", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(time.Hour), now, now.AddDate(1, 0, 0))

	if _, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil); err == nil {
		t.Fatal("Load with publish_at after sign_from succeeded, want an error")
	}
}

// TestLoad_PublishWindowShorterThanCacheTTLRefuses is ADR-0015's own
// refusal condition: "the active key's publish_at is not at least
// consumer_JWKS_cache_TTL before its sign_from."
//
// Negative control: with this check removed from Load, this test failed --
// a keyset published only 1 minute before a 10-minute cache TTL loaded
// successfully. Verified by hand, restored before committing.
func TestLoad_PublishWindowShorterThanCacheTTLRefuses(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeKeyFile(t, dir, "key-1", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-time.Minute), now, now.AddDate(1, 0, 0)) // published only 1m before signing

	if _, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil); err == nil {
		t.Fatal("Load with a too-short publish window succeeded, want an error")
	}
}

// TestLoad_RetirementWindowTooShortRefuses is RS-09's retirement formula,
// exercised with two keys: the old key's retire_at must be at least
// max_access_token_TTL + clock_skew + consumer_JWKS_cache_TTL after the
// new key's sign_from.
func TestLoad_RetirementWindowTooShortRefuses(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	oldSignFrom := now.Add(-24 * time.Hour)
	newSignFrom := now
	// Required minimum: testMaxAccessTokenTTL + testClockSkew + testConsumerJWKSCacheTTL
	// = 5m + 30s + 10m = 15m30s after newSignFrom. Retiring 1 minute after is too soon.
	oldRetireAt := newSignFrom.Add(time.Minute)

	writeKeyFile(t, dir, "old", string(tokenvalidator.RS256), rsaKey(t),
		oldSignFrom.Add(-time.Hour), oldSignFrom, oldRetireAt)
	writeKeyFile(t, dir, "new", string(tokenvalidator.ES256), ecKey(t),
		newSignFrom.Add(-time.Hour), newSignFrom, now.AddDate(1, 0, 0))

	if _, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil); err == nil {
		t.Fatal("Load with a too-short retirement window succeeded, want an error")
	}
}

// TestLoad_ValidRotationSucceeds is the same scenario as the test above,
// with the old key's retire_at widened to satisfy the formula exactly --
// proving the previous test's failure is really about the window's length,
// not some other difference between the two fixtures.
func TestLoad_ValidRotationSucceeds(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	oldSignFrom := now.Add(-24 * time.Hour)
	newSignFrom := now
	minRetire := testMaxAccessTokenTTL + testClockSkew + testConsumerJWKSCacheTTL
	oldRetireAt := newSignFrom.Add(minRetire + time.Minute) // comfortably past the minimum

	writeKeyFile(t, dir, "old", string(tokenvalidator.RS256), rsaKey(t),
		oldSignFrom.Add(-time.Hour), oldSignFrom, oldRetireAt)
	writeKeyFile(t, dir, "new", string(tokenvalidator.ES256), ecKey(t),
		newSignFrom.Add(-time.Hour), newSignFrom, now.AddDate(1, 0, 0))

	ks, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	key, err := ks.Signing(now)
	if err != nil {
		t.Fatalf("Signing: %v", err)
	}
	if key.KID != "new" {
		t.Errorf("Signing(now) = %q, want %q (the key whose SignFrom is latest not after now)", key.KID, "new")
	}
	oldKey, err := ks.Signing(oldSignFrom.Add(time.Hour))
	if err != nil {
		t.Fatalf("Signing(old window): %v", err)
	}
	if oldKey.KID != "old" {
		t.Errorf("Signing(old window) = %q, want %q", oldKey.KID, "old")
	}
}

func TestLoad_DuplicateKIDRefuses(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeKeyFile(t, dir, "dup", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))
	// A second file pair whose metadata claims the SAME kid under a
	// different filename stem is still a duplicate kid, caught by content,
	// not just by colliding filenames.
	writeKeyFile(t, dir, "dup2", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))
	// Overwrite dup2's metadata kid to collide with "dup".
	meta := keyMetadata{KID: "dup", Algorithm: string(tokenvalidator.RS256), PublishAt: now.Add(-time.Hour), SignFrom: now, RetireAt: now.AddDate(1, 0, 0)}
	metaBytes, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(dir, "dup2.json"), metaBytes, 0o600); err != nil {
		t.Fatalf("overwrite metadata: %v", err)
	}

	if _, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil); err == nil {
		t.Fatal("Load with two files claiming the same kid succeeded, want an error")
	}
}

// TestLoad_DenylistedOnlyKeyRefuses is ADR-0015's emergency path applied
// to the degenerate case: denylisting the only key in the set leaves
// nothing to sign with, which must refuse to start exactly like an empty
// directory would (RNF-05).
//
// Negative control: with the `denied[key.KID]` filter removed from Load's
// loop, this test failed -- the denylisted key loaded anyway and Signing
// returned it. Verified by hand, restored before committing.
func TestLoad_DenylistedOnlyKeyRefuses(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeKeyFile(t, dir, "leaked", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))

	if _, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, Denylist{"leaked"}); err == nil {
		t.Fatal("Load with the only key denylisted succeeded, want an error")
	}
}

func TestLoad_DenylistedKeyExcludedButOthersUsable(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	minRetire := testMaxAccessTokenTTL + testClockSkew + testConsumerJWKSCacheTTL
	writeKeyFile(t, dir, "leaked", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-48*time.Hour), now.Add(-24*time.Hour), now.Add(minRetire+time.Minute))
	writeKeyFile(t, dir, "good", string(tokenvalidator.ES256), ecKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))

	ks, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, Denylist{"leaked"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	key, err := ks.Signing(now)
	if err != nil {
		t.Fatalf("Signing: %v", err)
	}
	if key.KID != "good" {
		t.Errorf("Signing = %q, want %q", key.KID, "good")
	}
	for _, k := range ks.Published(now) {
		if k.KID == "leaked" {
			t.Error("the denylisted key is still Published")
		}
	}
}

func TestPublished_WindowBoundaries(t *testing.T) {
	dir := t.TempDir()
	publishAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signFrom := publishAt.Add(time.Hour)
	retireAt := signFrom.Add(24 * time.Hour)
	writeKeyFile(t, dir, "key-1", string(tokenvalidator.RS256), rsaKey(t), publishAt, signFrom, retireAt)

	ks, err := Load(dir, time.Minute, time.Minute, time.Minute, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := ks.Published(publishAt.Add(-time.Second)); len(got) != 0 {
		t.Errorf("Published before publish_at = %v, want empty", got)
	}
	if got := ks.Published(publishAt); len(got) != 1 {
		t.Errorf("Published at publish_at = %v, want exactly the one key", got)
	}
	if got := ks.Published(retireAt.Add(-time.Second)); len(got) != 1 {
		t.Errorf("Published just before retire_at = %v, want exactly the one key", got)
	}
	if got := ks.Published(retireAt); len(got) != 0 {
		t.Errorf("Published at retire_at = %v, want empty (retire_at is exclusive)", got)
	}
}

func TestSigning_NoKeySignsYetReturnsErrNoSigningKey(t *testing.T) {
	dir := t.TempDir()
	future := time.Now().Add(24 * time.Hour)
	writeKeyFile(t, dir, "key-1", string(tokenvalidator.RS256), rsaKey(t),
		future.Add(-time.Hour), future, future.AddDate(1, 0, 0))

	ks, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ks.Signing(time.Now()); !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("Signing(now), before the only key's sign_from = %v, want ErrNoSigningKey", err)
	}
}

// TestJWKS_NoPrivateParameters is #24's own done-when, asserted on the
// marshalled JSON itself rather than by review: an RSA private key's JWK
// form carries "d" (the private exponent), "p" and "q" (the primes); an
// ECDSA private key's carries "d". None of those fields may appear.
func TestJWKS_NoPrivateParameters(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	minRetire := testMaxAccessTokenTTL + testClockSkew + testConsumerJWKSCacheTTL
	writeKeyFile(t, dir, "rsa-key", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-48*time.Hour), now.Add(-24*time.Hour), now.Add(minRetire+time.Minute))
	writeKeyFile(t, dir, "ec-key", string(tokenvalidator.ES256), ecKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))

	ks, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	jwksBytes, err := ks.JWKS(now)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	var parsed struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwksBytes, &parsed); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(parsed.Keys) != 2 {
		t.Fatalf("JWKS has %d keys, want 2: %s", len(parsed.Keys), jwksBytes)
	}
	for _, k := range parsed.Keys {
		for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, present := k[privateField]; present {
				t.Errorf("JWKS key %v carries private parameter %q: %s", k["kid"], privateField, jwksBytes)
			}
		}
	}
}

func TestAsKeySource_ResolvesPublishedKID(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeKeyFile(t, dir, "key-1", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))
	ks, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	source := ks.AsKeySource()
	pub, alg, err := source.Key(t.Context(), "key-1")
	if err != nil {
		t.Fatalf("Key(key-1): %v", err)
	}
	if alg != tokenvalidator.RS256 {
		t.Errorf("Key algorithm = %v, want RS256", alg)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("Key public key type = %T, want *rsa.PublicKey", pub)
	}

	if _, _, err := source.Key(t.Context(), "never-existed"); !errors.Is(err, ErrUnknownKID) {
		t.Errorf("Key(never-existed) error = %v, want ErrUnknownKID", err)
	}
}

// TestKey_SigningProducesKIDHeader is #24's done-when "every token carries
// kid," proven against a real signature rather than by inspecting Key's
// fields: Key.JWK() is what a caller (ultimately #30's /token handler)
// would pass to jws.Sign, and this confirms the kid it carries round-trips
// into the actual JWS protected header.
//
// Negative control: with the `signingKey.Set(jwk.KeyIDKey, k.KID)` call
// removed from Key.JWK, this test failed -- the parsed header had no kid
// at all. Verified by hand, restored before committing.
func TestKey_SigningProducesKIDHeader(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeKeyFile(t, dir, "signing-key", string(tokenvalidator.RS256), rsaKey(t),
		now.Add(-time.Hour), now, now.AddDate(1, 0, 0))
	ks, err := Load(dir, testClockSkew, testMaxAccessTokenTTL, testConsumerJWKSCacheTTL, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	key, err := ks.Signing(now)
	if err != nil {
		t.Fatalf("Signing: %v", err)
	}

	signingJWK, err := key.JWK()
	if err != nil {
		t.Fatalf("Key.JWK: %v", err)
	}

	signed, err := jws.Sign([]byte(`{"sub":"alice"}`), jws.WithKey(jwa.RS256(), signingJWK))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}

	msg, err := jws.Parse(signed)
	if err != nil {
		t.Fatalf("jws.Parse: %v", err)
	}
	headers := msg.Signatures()[0].ProtectedHeaders()
	kid, ok := headers.KeyID()
	if !ok {
		t.Fatal("signed JWS has no kid in its protected header")
	}
	if kid != "signing-key" {
		t.Errorf("JWS kid = %v, want %q", kid, "signing-key")
	}
}

// TestKey_StringAndFormatRedactPrivate is #24's third done-when, the
// fmt-based half: fmt's default struct formatting does NOT actually
// dereference a pointer nested inside a struct field (Private is a
// crypto.Signer holding *rsa.PrivateKey, one level down from Key), so %v
// on a whole Key value prints the pointer's address either way, with or
// without a String method -- confirmed by hand before writing String and
// GoString, specifically so this comment does not overstate what they
// fix. What they add is an explicit, intentional redaction that does not
// depend on that incidental nesting behavior continuing to hold if Key's
// shape ever changes. See TestKey_MarshalJSON_RedactsPrivate below for
// the leak that is real and current: this project's own structured logger
// is JSON-based, and json.Marshal has no such nesting exemption.
//
// Negative control: with String/GoString removed, this test failed on the
// "mentions redaction" half only -- rendering the whole struct still did
// not leak the exponent even then, which is the asymmetry this comment
// exists to document. Verified by hand, restored before committing.
func TestKey_StringAndFormatRedactPrivate(t *testing.T) {
	signer := rsaKey(t)
	key := Key{KID: "key-1", Algorithm: tokenvalidator.RS256, Private: signer, SignFrom: time.Now()}

	privateDecimal := signer.D.String()

	for _, rendered := range []string{
		fmt.Sprintf("%v", key), //nolint:gocritic // deliberately the %v path a careless caller would use first, not a style choice
		fmt.Sprintf("%+v", key),
		fmt.Sprintf("%#v", key),
		key.String(),
	} {
		if strings.Contains(rendered, privateDecimal) {
			t.Errorf("rendering %q contains the raw private exponent", rendered)
		}
		if !strings.Contains(rendered, "redacted") {
			t.Errorf("rendering %q does not mention redaction", rendered)
		}
	}
}

// TestKey_MarshalJSON_RedactsPrivate is #24's third done-when against the
// leak that is actually reachable in this project: slog's JSON handler
// (cmd/usher's structured logger, #23) falls back to json.Marshal for any
// attribute with no LogValuer or MarshalJSON of its own. Without this
// override, logging a Key value through it -- h.logger.Error("...", "key",
// someKey), a plausible mistake in a future issue that handles a loading
// failure -- would serialize rsa.PrivateKey's exported D and Primes fields
// into the log record in the clear. fmt.Stringer (the previous test) is
// not consulted on this path at all.
//
// Negative control: with Key's MarshalJSON method removed, this test
// failed -- the real private exponent's decimal digits appeared directly
// in the JSON log record slog produced. Verified by hand, restored before
// committing.
func TestKey_MarshalJSON_RedactsPrivate(t *testing.T) {
	signer := rsaKey(t)
	key := Key{KID: "key-1", Algorithm: tokenvalidator.RS256, Private: signer, SignFrom: time.Now()}
	privateDecimal := signer.D.String()

	var buf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Error("key operation failed", "key", key)

	out := buf.String()
	if strings.Contains(out, privateDecimal) {
		t.Fatalf("the JSON log record contains the raw private exponent: %s", out)
	}
	if !strings.Contains(out, "redacted") {
		t.Errorf("the JSON log record does not mention redaction: %s", out)
	}
}
