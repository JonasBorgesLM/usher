package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeCodeStore and fakeFamilyStore are small, controllable stand-ins.
// CodeStore's own atomicity is proven elsewhere, against real Redis
// (internal/store/redis's integration tests, this same issue); what this
// file tests is ConsumeCode's own orchestration logic over the
// interfaces, which a fake is the right tool for.
type fakeCodeStore struct {
	codes      map[string]Code
	tombstones map[string]string
}

func newFakeCodeStore() *fakeCodeStore {
	return &fakeCodeStore{codes: map[string]Code{}, tombstones: map[string]string{}}
}

func (f *fakeCodeStore) Save(_ context.Context, c Code) error {
	if _, exists := f.codes[c.Value]; exists {
		return ErrCodeExists
	}
	f.codes[c.Value] = c
	return nil
}

func (f *fakeCodeStore) Consume(_ context.Context, value string) (Code, error) {
	c, ok := f.codes[value]
	if !ok {
		return Code{}, ErrCodeNotFound
	}
	delete(f.codes, value)
	return c, nil
}

func (f *fakeCodeStore) Tombstone(_ context.Context, value, familyID string, _ time.Duration) error {
	f.tombstones[value] = familyID
	return nil
}

func (f *fakeCodeStore) TombstonedFamily(_ context.Context, value string) (familyID string, found bool, err error) {
	familyID, found = f.tombstones[value]
	return familyID, found, nil
}

// fakeFamilyStore's tokens map is Rotate's own tiny model of
// refresh_tokens: a hash exists once seeded (seedToken, or by a prior
// Rotate's own insert of next) and maps to whether it has been consumed
// — the same shape FamilyStore.Rotate's real compare-and-set checks
// against a real table, used here by both ConsumeCode's tests (which
// never touch it) and RotateRefreshToken's own (#36).
type fakeFamilyStore struct {
	mu      sync.Mutex
	revoked map[string]string // familyID -> reason
	tokens  map[[32]byte]bool // hash -> consumed
}

func newFakeFamilyStore() *fakeFamilyStore {
	return &fakeFamilyStore{revoked: map[string]string{}, tokens: map[[32]byte]bool{}}
}

// seedToken records hash as already existing, consumed or not —
// RotateRefreshToken's own tests use this in place of CreateFamily,
// which this fake does not implement.
func (f *fakeFamilyStore) seedToken(hash [32]byte, consumed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[hash] = consumed
}

func (f *fakeFamilyStore) CreateFamily(context.Context, Family, RefreshToken) (string, error) {
	panic("not used by ConsumeCode or RotateRefreshToken")
}

// Rotate mirrors the real store's own compare-and-set: a hash that does
// not exist, or already consumed, is reuse (false, nil); otherwise it is
// marked consumed and next is recorded unconsumed, in the same call —
// this fake has no concurrent callers of its own to race, so a mutex is
// enough to make it a correct, if not atomic-under-contention, stand-in.
func (f *fakeFamilyStore) Rotate(_ context.Context, hash [32]byte, next RefreshToken) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	consumed, exists := f.tokens[hash]
	if !exists || consumed {
		return false, nil
	}
	f.tokens[hash] = true
	f.tokens[next.Hash] = false
	return true, nil
}

func (f *fakeFamilyStore) Revoke(_ context.Context, familyID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, already := f.revoked[familyID]; already {
		return nil // idempotent, matching the real store's own contract
	}
	f.revoked[familyID] = reason
	return nil
}

func (f *fakeFamilyStore) RevokeAllForSubject(context.Context, string, string) error {
	panic("not used by ConsumeCode or RotateRefreshToken")
}

func (f *fakeFamilyStore) Lookup(context.Context, [32]byte) (Family, RefreshToken, error) {
	panic("not used by ConsumeCode or RotateRefreshToken")
}

const (
	testValue       = "test-code-value"
	testClientID    = "client-1"
	testRedirectURI = "https://client.example/callback"
)

func testVerifierAndChallenge() (verifier, challenge string) {
	verifier = "a-real-pkce-verifier-with-enough-entropy-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func TestConsumeCode_Success(t *testing.T) {
	verifier, challenge := testVerifierAndChallenge()
	codes := newFakeCodeStore()
	families := newFakeFamilyStore()
	if err := codes.Save(context.Background(), Code{
		Value: testValue, ClientID: testClientID, RedirectURI: testRedirectURI,
		CodeChallenge: challenge, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := ConsumeCode(context.Background(), codes, families, testValue, testClientID, testRedirectURI, verifier)
	if err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
	if got.Value != testValue {
		t.Errorf("ConsumeCode returned %+v", got)
	}
}

func TestConsumeCode_ClientIDMismatchIsInvalidGrant(t *testing.T) {
	verifier, challenge := testVerifierAndChallenge()
	codes := newFakeCodeStore()
	if err := codes.Save(context.Background(), Code{
		Value: testValue, ClientID: testClientID, RedirectURI: testRedirectURI,
		CodeChallenge: challenge, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, err := ConsumeCode(context.Background(), codes, newFakeFamilyStore(), testValue, "a-different-client", testRedirectURI, verifier)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("ConsumeCode with a client_id mismatch = %v, want ErrInvalidGrant", err)
	}
}

func TestConsumeCode_RedirectURIMismatchIsInvalidGrant(t *testing.T) {
	verifier, challenge := testVerifierAndChallenge()
	codes := newFakeCodeStore()
	if err := codes.Save(context.Background(), Code{
		Value: testValue, ClientID: testClientID, RedirectURI: testRedirectURI,
		CodeChallenge: challenge, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, err := ConsumeCode(context.Background(), codes, newFakeFamilyStore(), testValue, testClientID, "https://attacker.example/callback", verifier)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("ConsumeCode with a redirect_uri mismatch = %v, want ErrInvalidGrant", err)
	}
}

// TestConsumeCode_PKCEMismatchIsInvalidGrant is RS-01's re-verification at
// consumption: a code_verifier that does not hash to the stored
// code_challenge is refused, even with every other binding correct.
func TestConsumeCode_PKCEMismatchIsInvalidGrant(t *testing.T) {
	_, challenge := testVerifierAndChallenge()
	codes := newFakeCodeStore()
	if err := codes.Save(context.Background(), Code{
		Value: testValue, ClientID: testClientID, RedirectURI: testRedirectURI,
		CodeChallenge: challenge, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, err := ConsumeCode(context.Background(), codes, newFakeFamilyStore(), testValue, testClientID, testRedirectURI, "the-wrong-verifier")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("ConsumeCode with the wrong code_verifier = %v, want ErrInvalidGrant", err)
	}
}

// TestConsumeCode_ReplayWithLiveTombstoneRevokesFamily is the issue's
// second done-when: a replay within the tombstone window revokes the
// family it produced.
//
// Negative control: with the `revokeReplayedFamily` call removed from
// ConsumeCode's failure branch (replaced with a direct `return Code{},
// ErrInvalidGrant`), this test failed -- the error was still
// ErrInvalidGrant (RS-25's ambiguity held), but the family was never
// marked revoked. Verified by hand, restored before committing.
func TestConsumeCode_ReplayWithLiveTombstoneRevokesFamily(t *testing.T) {
	codes := newFakeCodeStore()
	families := newFakeFamilyStore()
	// No code saved at all -- simulating a replay of a code already
	// consumed once, whose tombstone is still live.
	if err := codes.Tombstone(context.Background(), testValue, "family-1", time.Hour); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}

	_, err := ConsumeCode(context.Background(), codes, families, testValue, testClientID, testRedirectURI, "irrelevant")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("ConsumeCode on a replay = %v, want ErrInvalidGrant", err)
	}
	if reason, revoked := families.revoked["family-1"]; !revoked || reason != "reuse_detected" {
		t.Errorf("family-1 revoked=%v reason=%q, want revoked with reason \"reuse_detected\"", revoked, reason)
	}
}

// TestConsumeCode_NotFoundWithoutTombstoneDoesNotRevoke is the issue's
// third done-when: a code that never existed or already expired (no live
// tombstone) is plain invalid_grant, with nothing to revoke -- the stated
// residual, not a false-positive revocation.
func TestConsumeCode_NotFoundWithoutTombstoneDoesNotRevoke(t *testing.T) {
	codes := newFakeCodeStore()
	families := newFakeFamilyStore()

	_, err := ConsumeCode(context.Background(), codes, families, "never-issued", testClientID, testRedirectURI, "irrelevant")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("ConsumeCode on an unknown code = %v, want ErrInvalidGrant", err)
	}
	if len(families.revoked) != 0 {
		t.Errorf("a family was revoked for a code with no live tombstone: %v", families.revoked)
	}
}
