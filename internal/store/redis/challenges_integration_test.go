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

// TestChallengeStore_PromptAndMaxAge_RoundTrip is #47's own addition:
// Prompt and MaxAge survive a real Redis round trip, including the "no
// max_age at all" case, which must come back nil rather than a zero
// duration (RF-11: a request that never asked for max_age is not the
// same as one that asked for max_age=0, "always re-authenticate").
func TestChallengeStore_PromptAndMaxAge_RoundTrip(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)
	ctx := context.Background()

	withMaxAge := testChallenge(clock, "challenge-with-max-age", 5*time.Minute)
	withMaxAge.Prompt = "login"
	maxAge := 30 * time.Second
	withMaxAge.MaxAge = &maxAge
	if err := store.Save(ctx, withMaxAge); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Get(ctx, "challenge-with-max-age")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Prompt != "login" {
		t.Errorf("Prompt = %q, want %q", got.Prompt, "login")
	}
	if got.MaxAge == nil || *got.MaxAge != maxAge {
		t.Errorf("MaxAge = %v, want %s", got.MaxAge, maxAge)
	}

	withoutMaxAge := testChallenge(clock, "challenge-without-max-age", 5*time.Minute)
	if err := store.Save(ctx, withoutMaxAge); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got2, err := store.Get(ctx, "challenge-without-max-age")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got2.MaxAge != nil {
		t.Errorf("MaxAge = %v, want nil (request carried none)", got2.MaxAge)
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

func TestChallengeStore_SetAuthenticated(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)
	ctx := context.Background()

	c := testChallenge(clock, "challenge-1", 5*time.Minute)
	if err := store.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	authTime := clock.now()
	if err := store.SetAuthenticated(ctx, "challenge-1", "alice@example.com", authTime); err != nil {
		t.Fatalf("SetAuthenticated: %v", err)
	}

	got, err := store.Get(ctx, "challenge-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Subject != "alice@example.com" {
		t.Errorf("Subject = %q, want %q", got.Subject, "alice@example.com")
	}
	// Unix-seconds precision, the same encoding every other time.Time
	// field in this store uses (ExpiresAt, Nonce's own expiry) -- .Equal
	// would fail on authTime's sub-second component, which the round
	// trip never claimed to preserve.
	if got.AuthTime.Unix() != authTime.Unix() {
		t.Errorf("AuthTime = %s, want %s", got.AuthTime, authTime)
	}
	// The rest of the challenge survives SetAuthenticated unchanged.
	if got.ClientID != c.ClientID || got.State != c.State {
		t.Errorf("SetAuthenticated altered other fields: got %+v", got)
	}
}

func TestChallengeStore_SetAuthenticatedOnUnknownChallengeFails(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)

	if err := store.SetAuthenticated(context.Background(), "never-existed", "alice@example.com", clock.now()); !errors.Is(err, session.ErrChallengeNotFound) {
		t.Fatalf("SetAuthenticated on an unknown challenge = %v, want ErrChallengeNotFound", err)
	}
}

func TestChallengeStore_GetUnknownChallengeFails(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestChallengeStore(t, clock)

	if _, err := store.Get(context.Background(), "never-existed"); !errors.Is(err, session.ErrChallengeNotFound) {
		t.Fatalf("Get on an unknown challenge = %v, want ErrChallengeNotFound", err)
	}
}
