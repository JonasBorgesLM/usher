package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func jwksDeps(t *testing.T) routerDeps {
	t.Helper()
	deps := testDeps(t)
	deps.Keyset = testKeyset(t, deps.Now())
	deps.ConsumerJWKSCacheTTL = 10 * time.Minute
	return deps
}

func getJWKS(t *testing.T, mux http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://usher.test/.well-known/jwks.json", http.NoBody)
	req.Host = "usher.test"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestJWKS_NoPrivateParameters is the issue's own first done-when,
// exercised through the real HTTP route rather than Keyset.JWKS directly
// (internal/keys' own TestJWKS_NoPrivateParameters already proves that
// function; this proves the handler actually calls it and writes exactly
// its output, not something else assembled by hand).
//
// No separate negative control was written for this one: the property is
// already guarded at two independent layers from #24 (Keyset.JWKS builds
// the JWKS from each key's public half alone, never touching Private; and
// Key.MarshalJSON redacts Private to the literal string "<redacted>" even
// if something did try to marshal a Key directly). This handler has no
// third path of its own that could reintroduce the leak -- it calls
// JWKS and writes the bytes it returns, nothing else -- so there is no
// protection unique to this file to remove and watch fail.
func TestJWKS_NoPrivateParameters(t *testing.T) {
	mux := newRouter(jwksDeps(t))
	rec := getJWKS(t, mux)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /.well-known/jwks.json = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var parsed struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal JWKS response: %v", err)
	}
	if len(parsed.Keys) == 0 {
		t.Fatal("JWKS response has no keys")
	}
	for _, k := range parsed.Keys {
		for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, present := k[privateField]; present {
				t.Errorf("JWKS response key %v carries private parameter %q: %s", k["kid"], privateField, rec.Body.String())
			}
		}
	}
}

// TestJWKS_CacheControlMatchesConsumerCacheTTL is the issue's own second
// done-when.
//
// Negative control: with the `w.Header().Set("Cache-Control", ...)` line
// removed from jwksHandler.ServeHTTP, this test failed -- the header was
// absent entirely. Verified by hand, restored before committing.
func TestJWKS_CacheControlMatchesConsumerCacheTTL(t *testing.T) {
	deps := jwksDeps(t)
	mux := newRouter(deps)
	rec := getJWKS(t, mux)

	want := fmt.Sprintf("public, max-age=%d", int(deps.ConsumerJWKSCacheTTL.Seconds()))
	if got := rec.Header().Get("Cache-Control"); got != want {
		t.Errorf("Cache-Control = %q, want %q", got, want)
	}
}

func TestJWKS_ContentType(t *testing.T) {
	mux := newRouter(jwksDeps(t))
	rec := getJWKS(t, mux)

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
}
