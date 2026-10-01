//go:build integration

package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JonasBorgesLM/usher/internal/session"
)

func newTestChallengeStore(t *testing.T, clock *fakeClock) *ChallengeStore {
	t.Helper()
	client := newTestRedis(t, "noeviction.conf")
	return NewChallengeStore(client, WithChallengeClock(clock.now))
}

func testChallenge(clock *fakeClock, id string, ttl time.Duration) session.Challenge {
	return session.Challenge{
		ID:            id,
		ClientID:      "client-1",
		RedirectURI:   "https://client.example/callback",
		Scope:         []string{"openid"},
		State:         "xyz123",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		ExpiresAt:     clock.now().Add(ttl),
	}
}

func TestChallengeStore_SaveAndGet_RoundTrip(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)
	ctx := context.Background()

	c := testChallenge(clock, "challenge-1", 5*time.Minute)
	if err := store.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(ctx, "challenge-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClientID != c.ClientID || got.RedirectURI != c.RedirectURI || got.State != c.State {
		t.Errorf("Get: got %+v, want %+v", got, c)
	}
}

// TestChallengeStore_ReplayAfterUseRejected is the issue's first
// done-when: Consume is single-use, and a second Consume of the same id
// is rejected rather than returning the challenge again.
//
// Negative control: with Consume changed from GetDel to a plain Get (read
// without deleting), this test failed -- the second Consume call
// succeeded and returned the same challenge. Verified by hand, restored
// before committing.
func TestChallengeStore_ReplayAfterUseRejected(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)
	ctx := context.Background()

	c := testChallenge(clock, "challenge-1", 5*time.Minute)
	if err := store.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	first, err := store.Consume(ctx, "challenge-1")
	if err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if first.ID != "challenge-1" {
		t.Errorf("first Consume returned %+v", first)
	}

	if _, err := store.Consume(ctx, "challenge-1"); !errors.Is(err, session.ErrChallengeNotFound) {
		t.Fatalf("second Consume (replay) = %v, want ErrChallengeNotFound", err)
	}
}

// TestChallengeStore_ExpiresAtItsLifetime is the issue's second
// done-when, with a fake clock rather than a real wait: a challenge past
// its RF-12 lifetime is refused by both Get and Consume.
//
// Negative control: with the `!s.now().Before(c.ExpiresAt)` check removed
// from both Get and Consume, this test failed -- the expired challenge
// was returned successfully by both. Verified by hand, restored before
// committing.
func TestChallengeStore_ExpiresAtItsLifetime(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)
	ctx := context.Background()

	c := testChallenge(clock, "challenge-1", 5*time.Minute)
	if err := store.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	clock.advance(5*time.Minute + time.Second)

	if _, err := store.Get(ctx, "challenge-1"); !errors.Is(err, session.ErrChallengeNotFound) {
		t.Fatalf("Get after expiry = %v, want ErrChallengeNotFound", err)
	}
	if _, err := store.Consume(ctx, "challenge-1"); !errors.Is(err, session.ErrChallengeNotFound) {
		t.Fatalf("Consume after expiry = %v, want ErrChallengeNotFound", err)
	}
}

func TestChallengeStore_SetSubject(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)
	ctx := context.Background()

	c := testChallenge(clock, "challenge-1", 5*time.Minute)
	if err := store.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.SetSubject(ctx, "challenge-1", "alice@example.com"); err != nil {
		t.Fatalf("SetSubject: %v", err)
	}

	got, err := store.Get(ctx, "challenge-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Subject != "alice@example.com" {
		t.Errorf("Subject = %q, want %q", got.Subject, "alice@example.com")
	}
	// The rest of the challenge survives SetSubject unchanged.
	if got.ClientID != c.ClientID || got.State != c.State {
		t.Errorf("SetSubject altered other fields: got %+v", got)
	}
}

func TestChallengeStore_SetSubjectOnUnknownChallengeFails(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)

	if err := store.SetSubject(context.Background(), "never-existed", "alice@example.com"); !errors.Is(err, session.ErrChallengeNotFound) {
		t.Fatalf("SetSubject on an unknown challenge = %v, want ErrChallengeNotFound", err)
	}
}

func TestChallengeStore_GetUnknownChallengeFails(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)

	if _, err := store.Get(context.Background(), "never-existed"); !errors.Is(err, session.ErrChallengeNotFound) {
		t.Fatalf("Get on an unknown challenge = %v, want ErrChallengeNotFound", err)
	}
}
