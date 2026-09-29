//go:build integration

package postgres

import (
	"context"
	"testing"

	"github.com/JonasBorgesLM/usher/internal/identity"
)

// weakParams matches internal/identity's own test fixture in shape (small,
// fast) but is defined again here rather than exported from that package:
// exporting a "weak" set of Argon2id parameters for tests to import would be
// an easy thing to import by accident into non-test code.
var weakParams = identity.Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// TestLoginAgainstWeakerParamsRehashesTheRecord is issue #14's own done-when,
// exercised against a real UserStore rather than a fake: a record hashed
// under weaker-than-current parameters, once it verifies successfully, gets
// its password_hash replaced -- transparently, with no separate migration
// (ADR-0005). This is what a real login handler will do once one exists
// (#16); here the three calls it will make (VerifyPassword, NeedsRehash,
// UserStore.UpdateHash) are proven to compose correctly against Postgres.
func TestLoginAgainstWeakerParamsRehashesTheRecord(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	store := NewUserStore(pool)

	const password = "correct horse battery staple"
	oldHash, err := identity.HashPassword(password, weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	userID, err := store.CreateUser(ctx, SeedUser{Identifier: "rehash-flow@example.com", PasswordHash: oldHash, Role: "user"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// The login sequence this test proves: look up, verify, decide whether
	// to rehash, and if so, write the new hash back.
	u, ok, err := store.ByIdentifier(ctx, "rehash-flow@example.com")
	if err != nil || !ok {
		t.Fatalf("ByIdentifier: ok=%v err=%v", ok, err)
	}
	valid, err := identity.VerifyPassword(password, u.PasswordHash)
	if err != nil || !valid {
		t.Fatalf("VerifyPassword: valid=%v err=%v", valid, err)
	}
	needsRehash, err := identity.NeedsRehash(u.PasswordHash, identity.DefaultParams)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if !needsRehash {
		t.Fatal("test fixture is broken: weakParams did not register as needing a rehash against DefaultParams")
	}
	newHash, err := identity.HashPassword(password, identity.DefaultParams)
	if err != nil {
		t.Fatalf("HashPassword (rehash): %v", err)
	}
	if err := store.UpdateHash(ctx, userID, newHash); err != nil {
		t.Fatalf("UpdateHash: %v", err)
	}

	// The record now reflects the rehash: the stored hash changed, the
	// password still verifies against it, and it no longer needs a rehash.
	after, ok, err := store.ByIdentifier(ctx, "rehash-flow@example.com")
	if err != nil || !ok {
		t.Fatalf("ByIdentifier after rehash: ok=%v err=%v", ok, err)
	}
	if after.PasswordHash == oldHash {
		t.Error("password_hash after a successful login with weaker params is unchanged")
	}
	valid, err = identity.VerifyPassword(password, after.PasswordHash)
	if err != nil || !valid {
		t.Fatalf("VerifyPassword after rehash: valid=%v err=%v", valid, err)
	}
	needsRehash, err = identity.NeedsRehash(after.PasswordHash, identity.DefaultParams)
	if err != nil {
		t.Fatalf("NeedsRehash after rehash: %v", err)
	}
	if needsRehash {
		t.Error("record still reports needing a rehash immediately after being rehashed to DefaultParams")
	}
}
