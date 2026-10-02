//go:build integration

package redis

import (
	"context"
	"testing"
	"time"
)

func newTestDenylist(t *testing.T) *Denylist {
	t.Helper()
	client := newTestRedis(t, "noeviction.conf")
	return NewDenylist(client)
}

// TestDenylist_AddThenContainsTrue is #38's own done-when, at the store
// level: a jti written through Add is reported revoked by Contains.
func TestDenylist_AddThenContainsTrue(t *testing.T) {
	d := newTestDenylist(t)
	ctx := context.Background()

	if err := d.Add(ctx, "jti-1", time.Minute); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := d.Contains(ctx, "jti-1")
	if err != nil {
		t.Fatalf("Contains: %v", err)
	}
	if !got {
		t.Error("Contains(jti-1) = false after Add, want true")
	}
}

// TestDenylist_UnknownJTIContainsFalse is the round trip's own negative
// space: a jti never added is not revoked.
func TestDenylist_UnknownJTIContainsFalse(t *testing.T) {
	d := newTestDenylist(t)

	got, err := d.Contains(context.Background(), "never-added")
	if err != nil {
		t.Fatalf("Contains: %v", err)
	}
	if got {
		t.Error("Contains(never-added) = true, want false")
	}
}

// TestDenylist_NonPositiveTTLIsANoOp is Add's own documented contract: a
// token whose remaining lifetime is already zero or negative (RF-12's
// own exp already passed) is not written at all.
//
// Negative control: with the `if ttl <= 0 { return nil }` guard removed
// from Add, this test failed -- Set was called with a non-positive TTL,
// which go-redis (and Redis itself) treats as "no expiry" (PERSIST),
// leaving the key denylisted forever instead of never written. Verified
// by hand, restored before committing.
func TestDenylist_NonPositiveTTLIsANoOp(t *testing.T) {
	d := newTestDenylist(t)
	ctx := context.Background()

	if err := d.Add(ctx, "already-expired", 0); err != nil {
		t.Fatalf("Add(ttl=0): %v", err)
	}
	if err := d.Add(ctx, "already-expired-negative", -time.Second); err != nil {
		t.Fatalf("Add(ttl<0): %v", err)
	}

	for _, jti := range []string{"already-expired", "already-expired-negative"} {
		got, err := d.Contains(ctx, jti)
		if err != nil {
			t.Fatalf("Contains(%s): %v", jti, err)
		}
		if got {
			t.Errorf("Contains(%s) = true, want false -- Add with a non-positive ttl must be a no-op", jti)
		}
	}
}

// TestDenylist_EntryExpiresAfterTTL proves this store actually relies on
// Redis's own TTL mechanism, rather than some in-process bookkeeping that
// would survive a restart incorrectly: a key added with a short, real TTL
// is gone once that TTL elapses, with no fake clock to fast-forward --
// Redis's own expiry is wall-clock, so this test waits on it for real
// rather than mocking time.
func TestDenylist_EntryExpiresAfterTTL(t *testing.T) {
	d := newTestDenylist(t)
	ctx := context.Background()

	if err := d.Add(ctx, "short-lived", 500*time.Millisecond); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if got, err := d.Contains(ctx, "short-lived"); err != nil || !got {
		t.Fatalf("Contains immediately after Add: got=%v err=%v, want true, nil", got, err)
	}

	time.Sleep(900 * time.Millisecond)

	got, err := d.Contains(ctx, "short-lived")
	if err != nil {
		t.Fatalf("Contains after TTL elapsed: %v", err)
	}
	if got {
		t.Error("Contains(short-lived) = true after its TTL elapsed, want false")
	}
}
