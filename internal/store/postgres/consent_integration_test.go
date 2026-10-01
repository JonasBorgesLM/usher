//go:build integration

package postgres

import (
	"context"
	"testing"
)

func newTestConsentFixture(t *testing.T) (*ConsentStore, string) {
	t.Helper()
	pool := newTestPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	users := NewUserStore(pool)
	userID, err := users.CreateUser(ctx, SeedUser{
		Identifier:   "consent-test@example.com",
		PasswordHash: testPasswordHash,
		Role:         "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return NewConsentStore(pool), userID
}

func TestConsentStore_GrantedBeforeAnyGrantIsOkFalse(t *testing.T) {
	store, userID := newTestConsentFixture(t)

	scope, ok, err := store.Granted(context.Background(), userID, "client-1")
	if err != nil {
		t.Fatalf("Granted: %v", err)
	}
	if ok {
		t.Fatalf("Granted: ok=true before any grant exists, scope=%v", scope)
	}
}

func TestConsentStore_GrantAndGranted_RoundTrip(t *testing.T) {
	store, userID := newTestConsentFixture(t)
	ctx := context.Background()

	if err := store.Grant(ctx, userID, "client-1", []string{"openid", "profile"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	scope, ok, err := store.Granted(ctx, userID, "client-1")
	if err != nil {
		t.Fatalf("Granted: %v", err)
	}
	if !ok {
		t.Fatal("Granted: ok=false after a grant")
	}
	if !equalScopeSet(scope, []string{"openid", "profile"}) {
		t.Errorf("Granted scope = %v, want [openid profile]", scope)
	}
}

// TestConsentStore_GrantReplacesPriorGrant is Grant's own documented
// contract: a second Grant for the same (subject, clientID) replaces the
// row rather than accumulating a second one. The caller (the /consent
// handler) is responsible for passing the union when that is the desired
// semantics; this test confirms Grant itself does not union on its own.
func TestConsentStore_GrantReplacesPriorGrant(t *testing.T) {
	store, userID := newTestConsentFixture(t)
	ctx := context.Background()

	if err := store.Grant(ctx, userID, "client-1", []string{"openid"}); err != nil {
		t.Fatalf("first Grant: %v", err)
	}
	if err := store.Grant(ctx, userID, "client-1", []string{"profile"}); err != nil {
		t.Fatalf("second Grant: %v", err)
	}

	scope, _, err := store.Granted(ctx, userID, "client-1")
	if err != nil {
		t.Fatalf("Granted: %v", err)
	}
	if !equalScopeSet(scope, []string{"profile"}) {
		t.Errorf("scope after a second Grant = %v, want [profile] (replaced, not unioned)", scope)
	}
}

func TestConsentStore_Revoke(t *testing.T) {
	store, userID := newTestConsentFixture(t)
	ctx := context.Background()

	if err := store.Grant(ctx, userID, "client-1", []string{"openid"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if err := store.Revoke(ctx, userID, "client-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, ok, err := store.Granted(ctx, userID, "client-1")
	if err != nil {
		t.Fatalf("Granted: %v", err)
	}
	if ok {
		t.Fatal("Granted: ok=true after Revoke")
	}
}

func TestConsentStore_RevokeOfNonexistentGrantIsNotAnError(t *testing.T) {
	store, userID := newTestConsentFixture(t)
	if err := store.Revoke(context.Background(), userID, "never-granted-client"); err != nil {
		t.Fatalf("Revoke of a never-granted (subject, client) pair = %v, want nil", err)
	}
}

func equalScopeSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]bool, len(got))
	for _, s := range got {
		seen[s] = true
	}
	for _, s := range want {
		if !seen[s] {
			return false
		}
	}
	return true
}
