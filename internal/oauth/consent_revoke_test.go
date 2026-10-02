package oauth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeConsentStore is consent_revoke_test.go's own small stand-in —
// ConsentStore's real behavior over Postgres is proven in
// internal/store/postgres's own tests; what this file tests is
// RevokeConsent's orchestration over the two interfaces.
type fakeConsentStore struct {
	mu      sync.Mutex
	granted map[[2]string][]string // [subject, clientID] -> scope
}

func newFakeConsentStore(subject, clientID string, scope []string) *fakeConsentStore {
	return &fakeConsentStore{granted: map[[2]string][]string{{subject, clientID}: scope}}
}

func (f *fakeConsentStore) Granted(_ context.Context, subject, clientID string) (scope []string, ok bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	scope, ok = f.granted[[2]string{subject, clientID}]
	return scope, ok, nil
}

func (f *fakeConsentStore) Grant(_ context.Context, subject, clientID string, scope []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.granted[[2]string{subject, clientID}] = scope
	return nil
}

func (f *fakeConsentStore) Revoke(_ context.Context, subject, clientID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.granted, [2]string{subject, clientID})
	return nil
}

// erroringConsentStore is RevokeConsent's own control fixture for "the
// consent half fails after the families half already succeeded" — the
// ordering TestRevokeConsent_FamiliesRevokedBeforeConsentRow exists to
// prove matters.
type erroringConsentStore struct {
	err error
}

func (e *erroringConsentStore) Granted(context.Context, string, string) (scope []string, ok bool, err error) {
	panic("not used")
}
func (e *erroringConsentStore) Grant(context.Context, string, string, []string) error {
	panic("not used")
}
func (e *erroringConsentStore) Revoke(context.Context, string, string) error { return e.err }

// fakeScopedFamilyStore is consent_revoke_test.go's own stand-in for
// oauth.FamilyStore — unlike consume_test.go's fakeFamilyStore (keyed by
// hash, with no subject/client of its own to scope by), RevokeConsent's
// tests need a fake that actually models which (subject, clientID) a
// family belongs to, so a cross-client or cross-subject leak would show
// up as a wrongly-revoked family rather than a panic.
type fakeScopedFamilyStore struct {
	mu       sync.Mutex
	families map[string]Family
}

func newFakeScopedFamilyStore(fams ...Family) *fakeScopedFamilyStore {
	m := map[string]Family{}
	for _, f := range fams {
		m[f.ID] = f
	}
	return &fakeScopedFamilyStore{families: m}
}

func (f *fakeScopedFamilyStore) family(id string) Family {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.families[id]
}

func (f *fakeScopedFamilyStore) CreateFamily(context.Context, Family, RefreshToken) (string, error) {
	panic("not used by RevokeConsent")
}
func (f *fakeScopedFamilyStore) Rotate(context.Context, [32]byte, RefreshToken) (bool, error) {
	panic("not used by RevokeConsent")
}
func (f *fakeScopedFamilyStore) Lookup(context.Context, [32]byte) (Family, RefreshToken, error) {
	panic("not used by RevokeConsent")
}
func (f *fakeScopedFamilyStore) Revoke(context.Context, string, string) error {
	panic("not used by RevokeConsent")
}
func (f *fakeScopedFamilyStore) RevokeAllForSubject(context.Context, string, string) error {
	panic("not used by RevokeConsent")
}

// RevokeForSubjectAndClient mirrors the real store's own scoped UPDATE
// (internal/store/postgres/families.go): only a family matching both
// subject and clientID, not yet revoked, is touched.
func (f *fakeScopedFamilyStore) RevokeForSubjectAndClient(_ context.Context, subject, clientID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, fam := range f.families {
		if fam.Subject != subject || fam.ClientID != clientID || fam.RevokedAt != nil {
			continue
		}
		now := time.Now()
		fam.RevokedAt = &now
		fam.RevokedReason = reason
		f.families[id] = fam
	}
	return nil
}

// erroringFamilyStoreForConsent fails RevokeForSubjectAndClient outright
// — RevokeConsent's own control fixture for "the families half itself
// fails," distinct from erroringFamilyStore (rotate_test.go), whose
// Rotate is the method under test there, not this one.
type erroringFamilyStoreForConsent struct {
	err error
}

func (e *erroringFamilyStoreForConsent) CreateFamily(context.Context, Family, RefreshToken) (string, error) {
	panic("not used")
}
func (e *erroringFamilyStoreForConsent) Rotate(context.Context, [32]byte, RefreshToken) (bool, error) {
	panic("not used")
}
func (e *erroringFamilyStoreForConsent) Lookup(context.Context, [32]byte) (Family, RefreshToken, error) {
	panic("not used")
}
func (e *erroringFamilyStoreForConsent) Revoke(context.Context, string, string) error {
	panic("not used")
}
func (e *erroringFamilyStoreForConsent) RevokeAllForSubject(context.Context, string, string) error {
	panic("not used")
}
func (e *erroringFamilyStoreForConsent) RevokeForSubjectAndClient(context.Context, string, string, string) error {
	return e.err
}

const (
	testConsentSubject   = "alice"
	testConsentClientA   = "client-a"
	testConsentClientB   = "client-b"
	testConsentOtherUser = "bob"
)

// TestRevokeConsent_RevokesOnlyFamiliesUnderThatClient is RF-13's own
// done-when: revoking consent for (subject, clientA) revokes clientA's
// family, never clientB's family under the same subject, and never
// another subject's family under clientA either.
//
// Not RS-tagged (RF-13 has no RS- id of its own), but given the same
// negative-control discipline anyway: with
// fakeScopedFamilyStore.RevokeForSubjectAndClient's `fam.ClientID !=
// clientID` half of its guard removed, this test failed — clientB's
// family (same subject) was revoked too. With the `fam.Subject !=
// subject` half removed instead, bob's family under clientA was also
// revoked. Both verified by hand, restored before committing.
func TestRevokeConsent_RevokesOnlyFamiliesUnderThatClient(t *testing.T) {
	famA := Family{ID: "fam-a", Subject: testConsentSubject, ClientID: testConsentClientA}
	famB := Family{ID: "fam-b", Subject: testConsentSubject, ClientID: testConsentClientB}
	famOther := Family{ID: "fam-other", Subject: testConsentOtherUser, ClientID: testConsentClientA}
	families := newFakeScopedFamilyStore(famA, famB, famOther)
	consents := newFakeConsentStore(testConsentSubject, testConsentClientA, []string{"profile"})

	if err := RevokeConsent(context.Background(), consents, families, testConsentSubject, testConsentClientA); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}

	if got := families.family("fam-a"); got.RevokedAt == nil || got.RevokedReason != "consent_revoked" {
		t.Errorf("fam-a (subject+client both match) = %+v, want revoked with reason consent_revoked", got)
	}
	if got := families.family("fam-b"); got.RevokedAt != nil {
		t.Errorf("fam-b (same subject, different client) = %+v, want untouched", got)
	}
	if got := families.family("fam-other"); got.RevokedAt != nil {
		t.Errorf("fam-other (same client, different subject) = %+v, want untouched", got)
	}

	if _, ok, _ := consents.Granted(context.Background(), testConsentSubject, testConsentClientA); ok {
		t.Error("consent row for (subject, clientA) still exists after RevokeConsent")
	}
}

// TestRevokeConsent_FamiliesRevokedBeforeConsentRow is the ordering
// RevokeConsent's own doc comment commits to: when the consent half
// fails, the families half has already committed, so no token this
// consent produced is left usable even though the consent row itself
// still exists (and the caller's returned error says so, for a retry).
//
// Negative control: swapping the two calls' order (consent first, then
// families) made this test fail — with families.Revoke... stubbed to
// never run after a failing consents.Revoke, fam-a was left unrevoked
// while the consent row was already gone. Verified by hand, restored
// before committing.
func TestRevokeConsent_FamiliesRevokedBeforeConsentRow(t *testing.T) {
	famA := Family{ID: "fam-a", Subject: testConsentSubject, ClientID: testConsentClientA}
	families := newFakeScopedFamilyStore(famA)
	wantErr := errors.New("boom")
	consents := &erroringConsentStore{err: wantErr}

	err := RevokeConsent(context.Background(), consents, families, testConsentSubject, testConsentClientA)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RevokeConsent error = %v, want it to wrap %v", err, wantErr)
	}
	if got := families.family("fam-a"); got.RevokedAt == nil || got.RevokedReason != "consent_revoked" {
		t.Errorf("fam-a = %+v, want already revoked despite the consent row's own delete failing", got)
	}
}

// TestRevokeConsent_FamiliesErrorStopsBeforeConsentRevoked confirms the
// other failure path never reaches the consent row at all: if revoking
// families itself fails, RevokeConsent must not then revoke consent
// anyway (which would leave the opposite, unsafe drift — no consent on
// record, but a family still live).
func TestRevokeConsent_FamiliesErrorStopsBeforeConsentRevoked(t *testing.T) {
	wantErr := errors.New("families store unavailable")
	families := &erroringFamilyStoreForConsent{err: wantErr}
	consents := newFakeConsentStore(testConsentSubject, testConsentClientA, []string{"profile"})

	err := RevokeConsent(context.Background(), consents, families, testConsentSubject, testConsentClientA)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RevokeConsent error = %v, want it to wrap %v", err, wantErr)
	}
	if _, ok, _ := consents.Granted(context.Background(), testConsentSubject, testConsentClientA); !ok {
		t.Error("consent row was revoked even though revoking families failed first")
	}
}
