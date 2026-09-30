package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeUserStore is a small, counting in-memory stand-in for UserStore.
// Authenticator's own logic — constant work, message symmetry, exactly-once
// verification — is pure business logic over the UserStore interface, not
// the store's own behavior (already proven against real Postgres in
// internal/store/postgres). A fake is the right tool for testing it: it
// lets these tests count calls and control return values precisely, which
// a real database would make slower and less deterministic for no benefit.
type fakeUserStore struct {
	users map[string]User
	calls int
}

func newFakeUserStore(users ...User) *fakeUserStore {
	m := make(map[string]User, len(users))
	for _, u := range users {
		m[u.Identifier] = u
	}
	return &fakeUserStore{users: m}
}

func (f *fakeUserStore) ByIdentifier(_ context.Context, identifier string) (User, bool, error) {
	f.calls++
	u, ok := f.users[identifier]
	return u, ok, nil
}

func (f *fakeUserStore) UpdateHash(_ context.Context, _, _ string) error { return nil }

// erroringUserStore returns err from every ByIdentifier call — for proving
// a lookup failure propagates distinguishably from a credential failure.
type erroringUserStore struct{ err error }

func (e erroringUserStore) ByIdentifier(context.Context, string) (User, bool, error) {
	return User{}, false, e.err
}
func (erroringUserStore) UpdateHash(context.Context, string, string) error { return nil }

func newTestAuthenticator(t *testing.T, store UserStore) *Authenticator {
	t.Helper()
	hasher, err := NewHasher(4, time.Second, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	auth, err := NewAuthenticator(store, hasher, weakParams)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return auth
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	encoded, err := HashPassword(password, weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return encoded
}

func TestAuthenticator_Attempt_CorrectPasswordSucceeds(t *testing.T) {
	store := newFakeUserStore(User{ID: "1", Identifier: "alice@example.com", PasswordHash: mustHash(t, "right password")})
	auth := newTestAuthenticator(t, store)

	result, err := auth.Attempt(context.Background(), "alice@example.com", "right password")
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if result.User.Identifier != "alice@example.com" {
		t.Errorf("Attempt result: got %+v", result)
	}
}

func TestAuthenticator_Attempt_WrongPasswordFails(t *testing.T) {
	store := newFakeUserStore(User{ID: "1", Identifier: "alice@example.com", PasswordHash: mustHash(t, "right password")})
	auth := newTestAuthenticator(t, store)

	_, err := auth.Attempt(context.Background(), "alice@example.com", "wrong password")
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("Attempt with the wrong password = %v, want ErrLoginFailed", err)
	}
}

func TestAuthenticator_Attempt_UnknownIdentifierFails(t *testing.T) {
	store := newFakeUserStore() // empty
	auth := newTestAuthenticator(t, store)

	_, err := auth.Attempt(context.Background(), "nobody@example.com", "anything")
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("Attempt for an unknown identifier = %v, want ErrLoginFailed", err)
	}
}

// TestAuthenticator_ResponsesAreByteIdentical is the issue's own wording:
// "Responses for unknown user and wrong password are byte-identical." Not
// errors.Is alone — the literal message text, since a caller building an
// HTTP response from err.Error() must not accidentally leak a difference
// neither of the two collapsed-to-ErrLoginFailed branches intended.
func TestAuthenticator_ResponsesAreByteIdentical(t *testing.T) {
	store := newFakeUserStore(User{ID: "1", Identifier: "alice@example.com", PasswordHash: mustHash(t, "right password")})
	auth := newTestAuthenticator(t, store)

	_, wrongPasswordErr := auth.Attempt(context.Background(), "alice@example.com", "wrong password")
	_, unknownIdentifierErr := auth.Attempt(context.Background(), "nobody@example.com", "anything")

	if wrongPasswordErr == nil || unknownIdentifierErr == nil {
		t.Fatalf("expected both attempts to fail: wrongPassword=%v unknownIdentifier=%v", wrongPasswordErr, unknownIdentifierErr)
	}
	if wrongPasswordErr.Error() != unknownIdentifierErr.Error() {
		t.Errorf("responses differ:\n  wrong password:     %q\n  unknown identifier: %q", wrongPasswordErr.Error(), unknownIdentifierErr.Error())
	}
}

// fakeAccountLimiter is a small, controllable stand-in for
// AccountRateLimiter. RS-22's own rule -- the account axis is checked
// identically for existing and non-existent identifiers -- is what these
// tests need to prove about Authenticator's wiring; a real moat.Limiter
// over real Redis (verified separately, in internal/store/redis) would
// only make that harder to control precisely.
type fakeAccountLimiter struct {
	allow bool
	calls []string // keys Allow was called with, in order
}

func (f *fakeAccountLimiter) Allow(_ context.Context, key string) bool {
	f.calls = append(f.calls, key)
	return f.allow
}

// TestAuthenticator_AccountAxisDeniesIdenticallyForExistingAndNonExistent
// is the issue's own wording: the account axis is checked before lookup,
// on the canonicalized identifier, so it cannot distinguish "this account
// exists and is rate limited" from "this account does not exist" -- both
// produce ErrRateLimited, and the limiter sees the same key shape either
// way.
//
// This test's own outcome (ErrRateLimited either way) does not change if
// the axis were checked after the lookup instead of before — the negative
// control that catches *that* reordering is
// TestAuthenticator_AccountAxisChecksBeforeLookup below, which asserts the
// store is never reached at all, not just that the final error matches.
func TestAuthenticator_AccountAxisDeniesIdenticallyForExistingAndNonExistent(t *testing.T) {
	limiter := &fakeAccountLimiter{allow: false}
	store := newFakeUserStore(User{ID: "1", Identifier: "alice@example.com", PasswordHash: mustHash(t, "right password")})
	hasher, err := NewHasher(4, time.Second, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	auth, err := NewAuthenticator(store, hasher, weakParams, WithAccountLimiter(limiter))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	_, existingErr := auth.Attempt(context.Background(), "alice@example.com", "right password")
	_, nonExistentErr := auth.Attempt(context.Background(), "nobody@example.com", "anything")

	if !errors.Is(existingErr, ErrRateLimited) {
		t.Errorf("existing-account attempt while rate limited = %v, want ErrRateLimited", existingErr)
	}
	if !errors.Is(nonExistentErr, ErrRateLimited) {
		t.Errorf("non-existent-account attempt while rate limited = %v, want ErrRateLimited", nonExistentErr)
	}
	if existingErr.Error() != nonExistentErr.Error() {
		t.Errorf("responses differ: %q vs %q", existingErr.Error(), nonExistentErr.Error())
	}
}

// TestAuthenticator_AccountAxisChecksBeforeLookup proves the ordering
// itself, not just the outcome: the limiter is consulted exactly once, on
// the canonical identifier, and the store is never reached at all when the
// axis denies — the store lookup happening first would not change
// Attempt's return value in this test, but it would mean an attacker's
// request always costs a database round trip before being throttled,
// which is exactly the asymmetry RS-22's account axis exists to avoid.
//
// Negative control: with the account-axis check moved to after
// `a.store.ByIdentifier`, this test observed the store being called (its
// own call count went from 0 to 1) before the limiter ever ran — verified
// by hand, restored before committing.
func TestAuthenticator_AccountAxisChecksBeforeLookup(t *testing.T) {
	limiter := &fakeAccountLimiter{allow: false}
	store := newFakeUserStore()
	auth := newTestAuthenticatorWithLimiter(t, store, limiter)

	if _, err := auth.Attempt(context.Background(), "Alice@Example.COM", "anything"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Attempt = %v, want ErrRateLimited", err)
	}
	if store.calls != 0 {
		t.Errorf("store was looked up %d times; want 0 — the account axis should have denied before any lookup", store.calls)
	}
	if len(limiter.calls) != 1 || limiter.calls[0] != "alice@example.com" {
		t.Errorf("limiter calls = %v, want exactly one call with the canonicalized identifier", limiter.calls)
	}
}

func newTestAuthenticatorWithLimiter(t *testing.T, store UserStore, limiter AccountRateLimiter) *Authenticator {
	t.Helper()
	hasher, err := NewHasher(4, time.Second, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	auth, err := NewAuthenticator(store, hasher, weakParams, WithAccountLimiter(limiter))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return auth
}

// TestAuthenticator_NoLimiterConfiguredNeverDenies is the zero-value case:
// an Authenticator built without WithAccountLimiter enforces no account
// axis at all, rather than panicking on a nil interface.
func TestAuthenticator_NoLimiterConfiguredNeverDenies(t *testing.T) {
	store := newFakeUserStore(User{ID: "1", Identifier: "alice@example.com", PasswordHash: mustHash(t, "right password")})
	auth := newTestAuthenticator(t, store) // no WithAccountLimiter

	if _, err := auth.Attempt(context.Background(), "alice@example.com", "right password"); err != nil {
		t.Fatalf("Attempt without a configured limiter: %v", err)
	}
}

// TestAuthenticator_CanonicalizesBeforeLookup is RS-35 wired into the login
// path, not just CanonicalizeIdentifier tested in isolation: a user stored
// under its canonical identifier is still found when Attempt is given a
// case-variant spelling of the same address.
//
// Negative control: with the CanonicalizeIdentifier call removed from
// Attempt's lookup, this test failed with ErrLoginFailed — the case-variant
// spelling no longer matched the stored identifier. Verified by hand,
// restored before committing.
func TestAuthenticator_CanonicalizesBeforeLookup(t *testing.T) {
	store := newFakeUserStore(User{ID: "1", Identifier: "alice@example.com", PasswordHash: mustHash(t, "right password")})
	auth := newTestAuthenticator(t, store)

	result, err := auth.Attempt(context.Background(), "Alice@Example.COM", "right password")
	if err != nil {
		t.Fatalf("Attempt with a case-variant identifier: %v", err)
	}
	if result.User.Identifier != "alice@example.com" {
		t.Errorf("Attempt result: got %+v", result)
	}
}

// TestAuthenticator_DummyPasswordItselfNeverAuthenticates guards the one
// case where the dummy hash's own validity would otherwise decide the
// outcome: if an attacker's guessed password happens to equal the literal
// dummyPassword constant — readable in this package's source — Verify
// against the dummy hash returns true. Attempt's `!ok ||` is what still
// fails that case; without it, guessing this one hardcoded string would
// authenticate as any non-existent identifier with a zero-value User.
//
// Negative control: with the `!ok ||` half of Attempt's final condition
// removed, this test failed — the dummy password authenticated against an
// identifier that was never created. Verified by hand, restored before
// committing.
func TestAuthenticator_DummyPasswordItselfNeverAuthenticates(t *testing.T) {
	auth := newTestAuthenticator(t, newFakeUserStore()) // no users at all

	result, err := auth.Attempt(context.Background(), "nobody@example.com", dummyPassword)
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("Attempt with the literal dummy password = (result=%+v, err=%v), want ErrLoginFailed", result, err)
	}
}

// TestAuthenticator_NonExistentPathCallsVerifierExactlyOnce is the issue's
// second done-when item: the shortcut RS-14 exists to forbid is skipping
// verification entirely once ByIdentifier reports ok=false. Counting the
// real Hasher's underlying verifyFn calls (not just observing the outcome)
// is what would catch that shortcut even if it happened to still return
// ErrLoginFailed by some other path.
//
// Negative control: with Attempt short-circuiting `if !ok { return
// LoginResult{}, ErrLoginFailed }` immediately after the lookup, before
// calling Verify at all, this test's non-existent case observed 0 calls
// instead of 1 — verified by hand, restored before committing.
func TestAuthenticator_NonExistentPathCallsVerifierExactlyOnce(t *testing.T) {
	hasher, err := NewHasher(4, time.Second, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	var verifyCalls int
	hasher.verifyFn = func(password, encoded string) (bool, error) {
		verifyCalls++
		return VerifyPassword(password, encoded)
	}

	auth, err := NewAuthenticator(newFakeUserStore(), hasher, weakParams)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	verifyCalls = 0
	if _, err := auth.Attempt(context.Background(), "nobody@example.com", "anything"); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("Attempt for an unknown identifier = %v, want ErrLoginFailed", err)
	}
	if verifyCalls != 1 {
		t.Errorf("verifier called %d times for a non-existent identifier, want exactly 1", verifyCalls)
	}
}

func TestAuthenticator_ExistingPathAlsoCallsVerifierExactlyOnce(t *testing.T) {
	hasher, err := NewHasher(4, time.Second, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	var verifyCalls int
	hasher.verifyFn = func(password, encoded string) (bool, error) {
		verifyCalls++
		return VerifyPassword(password, encoded)
	}

	store := newFakeUserStore(User{ID: "1", Identifier: "alice@example.com", PasswordHash: mustHash(t, "right password")})
	auth, err := NewAuthenticator(store, hasher, weakParams)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	verifyCalls = 0
	if _, err := auth.Attempt(context.Background(), "alice@example.com", "right password"); err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if verifyCalls != 1 {
		t.Errorf("verifier called %d times for an existing identifier, want exactly 1", verifyCalls)
	}
}

// TestAuthenticator_LookupErrorPropagatesDistinguishably proves a genuine
// infrastructure failure (the store is unreachable) is never silently
// folded into ErrLoginFailed — a caller mapping errors to HTTP status needs
// to tell "these credentials are wrong" (401) apart from "something is
// broken" (503, RNF-04's fail-closed).
func TestAuthenticator_LookupErrorPropagatesDistinguishably(t *testing.T) {
	boom := errors.New("boom: store unreachable")
	auth := newTestAuthenticator(t, erroringUserStore{err: boom})

	_, err := auth.Attempt(context.Background(), "anyone@example.com", "anything")
	if errors.Is(err, ErrLoginFailed) {
		t.Fatal("a store lookup error was reported as ErrLoginFailed; want it distinguishable")
	}
	if !errors.Is(err, boom) {
		t.Errorf("Attempt error = %v, want it to wrap the store's own error", err)
	}
}

// TestAuthenticator_HasherErrorPropagatesDistinguishably is the same
// principle applied to Hasher.ErrSaturated: a caller needs to map
// saturation to 503, not to the same outcome as a wrong password.
func TestAuthenticator_HasherErrorPropagatesDistinguishably(t *testing.T) {
	hasher, err := NewHasher(1, 10*time.Millisecond, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	acquired := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	hasher.verifyFn = func(string, string) (bool, error) {
		close(acquired)
		<-release
		return false, nil
	}

	store := newFakeUserStore(User{ID: "1", Identifier: "alice@example.com", PasswordHash: mustHash(t, "x")})
	auth, err := NewAuthenticator(store, hasher, weakParams)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	// Occupy the single slot so the next Attempt saturates.
	go func() { _, _ = auth.Attempt(context.Background(), "alice@example.com", "x") }()
	<-acquired // deterministic: proceed only once the slot is genuinely held

	_, attemptErr := auth.Attempt(context.Background(), "alice@example.com", "x")
	if errors.Is(attemptErr, ErrLoginFailed) {
		t.Fatal("a saturated Hasher was reported as ErrLoginFailed; want it distinguishable")
	}
	if !errors.Is(attemptErr, ErrSaturated) {
		t.Errorf("Attempt error = %v, want ErrSaturated", attemptErr)
	}
}
