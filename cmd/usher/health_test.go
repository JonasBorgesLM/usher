package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthzRoute_AlwaysOK(t *testing.T) {
	mux := newRouter(testDeps(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/healthz", http.NoBody)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestReadyzRoute_AllChecksPass(t *testing.T) {
	deps := testDeps(t)
	deps.ReadinessChecks = []ReadinessCheck{
		{Name: "postgres", Check: func(context.Context) error { return nil }},
		{Name: "redis", Check: func(context.Context) error { return nil }},
	}
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/readyz", http.NoBody)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz with all checks passing = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestReadyzRoute_OneFailingCheckReturns503 is the unit-level half of
// "/readyz fails when Redis is stopped" -- the integration test
// (readyz_integration_test.go) proves it against a real container; this
// proves the aggregation logic itself, and that every check still runs
// and is reported even once one has already failed.
//
// Negative control: with the `allOK = false` assignment removed from
// readinessHandler.ServeHTTP's failing branch, this test failed -- the
// response was 200 despite the "redis" check returning an error. Verified
// by hand, restored before committing.
func TestReadyzRoute_OneFailingCheckReturns503(t *testing.T) {
	deps := testDeps(t)
	deps.ReadinessChecks = []ReadinessCheck{
		{Name: "postgres", Check: func(context.Context) error { return nil }},
		{Name: "redis", Check: func(context.Context) error { return errors.New("connection refused") }},
	}
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/readyz", http.NoBody)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with a failing check = %d, want %d, body: %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}

	var body struct {
		Checks []readinessResult `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if len(body.Checks) != 2 {
		t.Fatalf("response reported %d checks, want 2: %+v", len(body.Checks), body.Checks)
	}
	for _, c := range body.Checks {
		if c.Name == "postgres" && !c.OK {
			t.Error("the passing postgres check was reported as failing")
		}
		if c.Name == "redis" && c.OK {
			t.Error("the failing redis check was reported as passing")
		}
	}
}
