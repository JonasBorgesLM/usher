//go:build integration

package redis

import (
	"context"
	"testing"

	"github.com/JonasBorgesLM/moat/ratelimit"
)

// TestAccountAxisDeniesWhenRedisIsUnavailable is RNF-04 against the real
// store this package builds, not a fake: a moat.ratelimit.Limiter over a
// redisstore.Store that NewRateLimitStore verified, once its Redis becomes
// unreachable, must deny rather than pass — moat's default FailClosed
// policy, which this project takes no option to override.
//
// Negative control: with ratelimit.WithFailureMode(ratelimit.FailOpen)
// added to the Limiter's construction, this test observed Allow return
// true against the same stopped container — verified by hand, not kept in
// the committed test.
func TestAccountAxisDeniesWhenRedisIsUnavailable(t *testing.T) {
	ctx := context.Background()
	client := newTestRedis(t, "noeviction.conf")

	store, err := NewRateLimitStore(client)
	if err != nil {
		t.Fatalf("NewRateLimitStore: %v", err)
	}

	// No WithFailureMode: FailClosed is the zero value, and this project
	// takes no option to change it for the account axis.
	limiter := ratelimit.New(5, 1, ratelimit.WithStore(store))

	if !limiter.Allow(ctx, "alice@example.com") {
		t.Fatal("Allow denied against a healthy Redis; want the first request admitted")
	}

	// Closing the client (rather than stopping the container, which would
	// race newTestRedis's own t.Cleanup) makes every further call fail with
	// a connection error — simulating "Redis is unreachable" deterministically,
	// without waiting on a real TCP timeout.
	if err := client.Close(); err != nil {
		t.Fatalf("close redis client: %v", err)
	}

	if limiter.Allow(ctx, "alice@example.com") {
		t.Error("Allow succeeded against an unavailable Redis; want RNF-04's fail-closed denial")
	}
}
