package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JonasBorgesLM/moat/ratelimit"
)

func TestNamespacedKeyFunc_PrefixesTheUnderlyingKey(t *testing.T) {
	inner := func(*http.Request) (string, error) { return "1.2.3.4", nil }
	fn := namespacedKeyFunc("login:", inner)

	got, err := fn(httpGetRequest(t))
	if err != nil {
		t.Fatalf("namespacedKeyFunc returned an error: %v", err)
	}
	if want := "login:1.2.3.4"; got != want {
		t.Errorf("namespacedKeyFunc key = %q, want %q", got, want)
	}
}

func TestNamespacedKeyFunc_PropagatesTheInnerError(t *testing.T) {
	innerErr := errors.New("boom")
	inner := func(*http.Request) (string, error) { return "", innerErr }
	fn := namespacedKeyFunc("login:", inner)

	_, err := fn(httpGetRequest(t))
	if !errors.Is(err, innerErr) {
		t.Errorf("namespacedKeyFunc error = %v, want %v", err, innerErr)
	}
}

// TestLoginAndAuthorizeLimiters_DoNotShareABucket is the regression for the
// bug namespacedKeyFunc fixes: loginLimiter and authorizeLimiter share one
// Store (WithStore's own doc comment says that is intended), but before this
// fix they also shared one bare IP key, so exhausting one route's budget
// exhausted the other's too -- RS-22's two deliberately different tiers
// collapsed into a single shared bucket. Found live, against the real compose
// stack, while writing scripts/probe-threats.sh for #52: six requests to
// /consent (loginLimiter) drove /authorize's (authorizeLimiter) own reported
// Remaining from 19 straight to 0.
//
// Seen failing: passing rawKeyFunc directly to both ratelimit.New calls below
// (reverting namespacedKeyFunc's two different prefixes, exactly what
// cmd/usher/main.go did before this fix) fails this test -- draining
// loginLimiter's one-token burst then leaves authorizeLimiter unable to
// allow a request its own, much larger, untouched burst should still cover.
func TestLoginAndAuthorizeLimiters_DoNotShareABucket(t *testing.T) {
	store := ratelimit.NewMemoryStore()
	defer store.Close()

	rawKeyFunc := func(*http.Request) (string, error) { return "198.51.100.7", nil }

	login := ratelimit.New(1, 0, ratelimit.WithStore(store), ratelimit.WithKeyFunc(namespacedKeyFunc("login:", rawKeyFunc)))
	authorize := ratelimit.New(20, 0, ratelimit.WithStore(store), ratelimit.WithKeyFunc(namespacedKeyFunc("authorize:", rawKeyFunc)))

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	loginHandler := login.Middleware(ok)
	authorizeHandler := authorize.Middleware(ok)

	rec := httptest.NewRecorder()
	loginHandler.ServeHTTP(rec, httpGetRequest(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("first request through loginLimiter = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	loginHandler.ServeHTTP(rec, httpGetRequest(t))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request through loginLimiter = %d, want 429 (its burst is 1)", rec.Code)
	}

	// authorizeLimiter has its own, much larger burst for the same client
	// and must still have all of it, untouched by loginLimiter's traffic.
	rec = httptest.NewRecorder()
	authorizeHandler.ServeHTTP(rec, httpGetRequest(t))
	if rec.Code != http.StatusOK {
		t.Errorf("request through authorizeLimiter = %d, want 200 -- starved by loginLimiter's traffic, the two limiters are sharing a bucket", rec.Code)
	}
}

func httpGetRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}
