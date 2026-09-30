//go:build integration

package redis

import (
	"context"
	"errors"
	"testing"

	"github.com/JonasBorgesLM/moat/redisstore"
	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// newTestRedis starts a real redis:7-alpine container under the given
// config file — REQUIREMENTS §10 forbids a fake here: a fake client can
// answer CONFIG GET however a test wants, which proves nothing about how
// redisstore's own sweep logic reacts to a real server's real reply shape.
func newTestRedis(t *testing.T, configFile string) *goredis.Client {
	t.Helper()
	ctx := context.Background()

	container, err := tcredis.Run(ctx, "redis:7-alpine", tcredis.WithConfigFile("testdata/"+configFile))
	if err != nil {
		t.Fatalf("start redis container (%s): %v", configFile, err)
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
	return client
}

func TestNewRateLimitStore_NoEvictionVerifiedAndSucceeds(t *testing.T) {
	client := newTestRedis(t, "noeviction.conf")

	store, err := NewRateLimitStore(client)
	if err != nil {
		t.Fatalf("NewRateLimitStore against a noeviction server: %v", err)
	}
	if !store.EvictionCheck().Verified() {
		t.Errorf("EvictionCheck() = %s, want Verified", store.EvictionCheck())
	}
}

// TestNewRateLimitStore_RefusesUnsafeEvictionPolicy is one half of the
// issue's own wording: "Startup against a Redis with allkeys-lru refuses."
//
// Negative control: with the `!check.Verified()` guard removed from
// NewRateLimitStore, this test failed to observe an error — verified by
// hand, restored before committing.
func TestNewRateLimitStore_RefusesUnsafeEvictionPolicy(t *testing.T) {
	client := newTestRedis(t, "unsafe-eviction.conf")

	_, err := NewRateLimitStore(client)
	if !errors.Is(err, ErrEvictionPolicyUnverified) {
		t.Fatalf("NewRateLimitStore against an allkeys-lru server = %v, want ErrEvictionPolicyUnverified", err)
	}
	if !errors.Is(err, redisstore.ErrUnsafeEvictionPolicy) {
		t.Errorf("error does not wrap redisstore.ErrUnsafeEvictionPolicy: %v", err)
	}
}

// TestNewRateLimitStore_RefusesWhenConfigIsUnavailable is the issue's other
// half: "against one without CONFIG refuses." This is the common case on
// managed Redis (ElastiCache, MemoryDB, Upstash, Azure Cache) — the check
// cannot be performed at all, and RNF-05 treats "not checked" the same as
// "checked and unsafe": both refuse to start, never a shrug.
//
// Negative control: with the `!check.Verified()` guard removed from
// NewRateLimitStore, this test failed to observe an error — verified by
// hand, restored before committing.
func TestNewRateLimitStore_RefusesWhenConfigIsUnavailable(t *testing.T) {
	client := newTestRedis(t, "config-disabled.conf")

	_, err := NewRateLimitStore(client)
	if !errors.Is(err, ErrEvictionPolicyUnverified) {
		t.Fatalf("NewRateLimitStore against a server with CONFIG disabled = %v, want ErrEvictionPolicyUnverified", err)
	}
}
