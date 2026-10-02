package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/JonasBorgesLM/usher/internal/audit"
)

func testHash(label string) [32]byte {
	var h [32]byte
	copy(h[:], label)
	return h
}

func TestRotateRefreshToken_Success(t *testing.T) {
	store := newFakeFamilyStore()
	hashA := testHash("token-a")
	hashB := testHash("token-b")
	store.seedToken(hashA, false)
	sink := audit.NewMemorySink()

	err := RotateRefreshToken(context.Background(), store, sink, hashA, RefreshToken{Hash: hashB, FamilyID: "family-1"})
	if err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}
	if consumed := store.tokens[hashA]; !consumed {
		t.Error("the presented token was not marked consumed")
	}
	if consumed, exists := store.tokens[hashB]; !exists || consumed {
		t.Error("the successor token was not recorded unconsumed")
	}
	if _, revoked := store.revoked["family-1"]; revoked {
		t.Error("a successful rotation revoked the family")
	}
	if len(sink.Events()) != 0 {
		t.Errorf("a successful rotation emitted %d events, want 0: %+v", len(sink.Events()), sink.Events())
	}
}

// TestRotateRefreshToken_ReuseRevokesFamilyAndEmitsAudit is #36's own
// second and third done-when: a reused (already-consumed) token revokes
// the family and emits a high-severity audit event.
//
// Negative control: with the `families.Revoke` call removed from
// RotateRefreshToken's reuse branch, this test failed — the error was
// still ErrInvalidGrant (RS-25's ambiguity held), but
// store.revoked["family-1"] was never set. Verified by hand, restored
// before committing.
func TestRotateRefreshToken_ReuseRevokesFamilyAndEmitsAudit(t *testing.T) {
	store := newFakeFamilyStore()
	hashA := testHash("token-a")
	hashB := testHash("token-b")
	store.seedToken(hashA, true) // already consumed -- this call is a replay
	sink := audit.NewMemorySink()

	err := RotateRefreshToken(context.Background(), store, sink, hashA, RefreshToken{Hash: hashB, FamilyID: "family-1"})
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("RotateRefreshToken on a reused token = %v, want ErrInvalidGrant", err)
	}
	if reason, revoked := store.revoked["family-1"]; !revoked || reason != "reuse_detected" {
		t.Errorf("family-1 revoked=%v reason=%q, want revoked with reason %q", revoked, reason, "reuse_detected")
	}

	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("reuse emitted %d events, want 1: %+v", len(events), events)
	}
	if events[0].Type != audit.EventRefreshReuse || events[0].Outcome != audit.OutcomeFailure {
		t.Errorf("event = %+v, want {Type: %q, Outcome: %q}", events[0], audit.EventRefreshReuse, audit.OutcomeFailure)
	}
}

// TestRotateRefreshToken_NilEmitterDoesNotPanic is a real finding from
// wiring this function into #37's /token handler: audit.Emitter is
// documented as an optional dependency everywhere else in this codebase
// ("nil emits nothing" -- cmd/usher/login.go's own h.emit), but calling
// Emit directly through a nil interface value panics regardless of what
// that convention says. A deployment that never wires RF-09 emission at
// all would panic on its very first reuse attempt.
//
// Negative control: with the `if emitter != nil` guard removed from
// RotateRefreshToken's reuse branch, this test panicked instead of
// returning ErrInvalidGrant. Verified by hand, restored before
// committing.
func TestRotateRefreshToken_NilEmitterDoesNotPanic(t *testing.T) {
	store := newFakeFamilyStore()
	store.seedToken(testHash("token-a"), true) // already consumed -- reuse

	err := RotateRefreshToken(context.Background(), store, nil, testHash("token-a"), RefreshToken{Hash: testHash("token-b"), FamilyID: "family-1"})
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("RotateRefreshToken with a nil emitter = %v, want ErrInvalidGrant", err)
	}
}

func TestRotateRefreshToken_UnknownHashIsInvalidGrant(t *testing.T) {
	store := newFakeFamilyStore()
	sink := audit.NewMemorySink()

	err := RotateRefreshToken(context.Background(), store, sink, testHash("never-issued"), RefreshToken{Hash: testHash("next"), FamilyID: "family-1"})
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("RotateRefreshToken on an unknown hash = %v, want ErrInvalidGrant", err)
	}
}

// TestRotateRefreshToken_RotateErrorPropagates confirms a genuine store
// error (not a reuse signal) is reported as-is, not swallowed into
// ErrInvalidGrant — RS-25's ambiguity is for the client-facing grant
// decision, not for this function's own caller losing visibility into an
// infrastructure failure (RNF-04).
func TestRotateRefreshToken_RotateErrorPropagates(t *testing.T) {
	store := &erroringFamilyStore{err: errors.New("boom")}
	sink := audit.NewMemorySink()

	err := RotateRefreshToken(context.Background(), store, sink, testHash("whatever"), RefreshToken{Hash: testHash("next"), FamilyID: "family-1"})
	if err == nil || errors.Is(err, ErrInvalidGrant) {
		t.Errorf("RotateRefreshToken on a store error = %v, want it to propagate the underlying error, not ErrInvalidGrant", err)
	}
}

// erroringFamilyStore is a minimal FamilyStore whose Rotate always fails
// -- RotateErrorPropagates' own fixture, distinct from fakeFamilyStore
// since that one has no way to simulate an infrastructure failure.
type erroringFamilyStore struct {
	err error
}

func (e *erroringFamilyStore) CreateFamily(context.Context, Family, RefreshToken) (string, error) {
	panic("not used")
}
func (e *erroringFamilyStore) Rotate(context.Context, [32]byte, RefreshToken) (bool, error) {
	return false, e.err
}
func (e *erroringFamilyStore) Revoke(context.Context, string, string) error { panic("not used") }
func (e *erroringFamilyStore) RevokeAllForSubject(context.Context, string, string) error {
	panic("not used")
}
func (e *erroringFamilyStore) Lookup(context.Context, [32]byte) (Family, RefreshToken, error) {
	panic("not used")
}
