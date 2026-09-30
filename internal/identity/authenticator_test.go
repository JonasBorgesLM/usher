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
