//go:build integration

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// TestReadyzRoute_FailsWhenRedisStopped is the issue's own integration-test
// done-when item. REQUIREMENTS §10 forbids a fake Redis here: the property
// under test is how a real connection behaves once its server stops
// answering, which a fake client cannot reproduce by construction — see
// internal/store/redis's own integration tests for the same reasoning.
func TestReadyzRoute_FailsWhenRedisStopped(t *testing.T) {
	ctx := context.Background()
	container, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		t.Fatalf("start redis container: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Logf("terminate redis container: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	opts, err := goredis.ParseURL(connStr)
	if err != nil {
		t.Fatalf("parse connection string %q: %v", connStr, err)
	}
	client := goredis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })

	deps := testDeps(t)
	deps.ReadinessChecks = []ReadinessCheck{
		{Name: "redis", Check: func(ctx context.Context) error { return client.Ping(ctx).Err() }},
	}
	mux := newRouter(deps)

	readyz := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/readyz", http.NoBody)
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := readyz(); rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz with Redis up = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if err := container.Stop(ctx, nil); err != nil {
		t.Fatalf("stop redis container: %v", err)
	}

	// Pinging a just-stopped container does not fail instantaneously --
	// the client's existing pooled connection takes a moment to notice the
	// peer is gone. Poll instead of asserting on the very next call.
	deadline := time.Now().Add(10 * time.Second)
	for {
		rec := readyz()
		if rec.Code == http.StatusServiceUnavailable {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET /readyz with Redis stopped = %d, want %d, body: %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
