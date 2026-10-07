//go:build integration

package postgres

import (
	"context"
	"testing"
)

const testPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$dGVzdC1zYWx0$dGVzdC1oYXNoLXZhbHVl" // #nosec G101 -- fixture, not a real credential

func TestUserStore_ByIdentifier_FoundAndNotFound(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	store := NewUserStore(pool)

	id, err := store.CreateUser(ctx, SeedUser{
		Identifier:   "found@example.com",
		PasswordHash: testPasswordHash,
		Role:         "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		u, ok, err := store.ByIdentifier(ctx, "found@example.com")
		if err != nil {
			t.Fatalf("ByIdentifier: %v", err)
		}
		if !ok {
			t.Fatal("ByIdentifier: ok=false for a user that exists")
		}
		if u.ID != id || u.Identifier != "found@example.com" || u.PasswordHash != testPasswordHash || u.Role != "user" {
			t.Errorf("ByIdentifier: got %+v", u)
		}
	})

	t.Run("not found returns ok=false, not an error", func(t *testing.T) {
		u, ok, err := store.ByIdentifier(ctx, "nobody@example.com")
		if err != nil {
			t.Fatalf("ByIdentifier: unexpected error for a missing user: %v", err)
		}
		if ok {
			t.Fatalf("ByIdentifier: ok=true for a user that was never created: %+v", u)
		}
	})
}

func TestUserStore_ByID_FoundAndNotFound(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	store := NewUserStore(pool)

	id, err := store.CreateUser(ctx, SeedUser{
		Identifier:   "found-by-id@example.com",
		PasswordHash: testPasswordHash,
		Role:         "admin",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		u, ok, err := store.ByID(ctx, id)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if !ok {
			t.Fatal("ByID: ok=false for a user that exists")
		}
		if u.ID != id || u.Identifier != "found-by-id@example.com" || u.PasswordHash != testPasswordHash || u.Role != "admin" {
			t.Errorf("ByID: got %+v", u)
		}
	})

	t.Run("not found returns ok=false, not an error", func(t *testing.T) {
		u, ok, err := store.ByID(ctx, "00000000-0000-0000-0000-000000000000")
		if err != nil {
			t.Fatalf("ByID: unexpected error for a missing user: %v", err)
		}
		if ok {
			t.Fatalf("ByID: ok=true for a user that was never created: %+v", u)
		}
	})
}

func TestUserStore_UpdateHash(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	store := NewUserStore(pool)

	id, err := store.CreateUser(ctx, SeedUser{
		Identifier:   "rehash@example.com",
		PasswordHash: testPasswordHash,
		Role:         "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	const newHash = "$argon2id$v=19$m=131072,t=4,p=4$bmV3LXNhbHQ$bmV3LWhhc2gtdmFsdWU" // #nosec G101 -- fixture
	if err := store.UpdateHash(ctx, id, newHash); err != nil {
		t.Fatalf("UpdateHash: %v", err)
	}

	u, ok, err := store.ByIdentifier(ctx, "rehash@example.com")
	if err != nil || !ok {
		t.Fatalf("ByIdentifier after UpdateHash: ok=%v err=%v", ok, err)
	}
	if u.PasswordHash != newHash {
		t.Errorf("password_hash after UpdateHash: got %q, want %q", u.PasswordHash, newHash)
	}
}

func TestUserStore_UpdateHash_UnknownUserFails(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	store := NewUserStore(pool)

	err := store.UpdateHash(ctx, "00000000-0000-0000-0000-000000000000", testPasswordHash)
	if err == nil {
		t.Fatal("UpdateHash succeeded against a user id that was never created; want an error")
	}
}

// TestUserStore_CreateUser_DuplicateIdentifierFails is RS-35's one-canonical-
// identifier rule, enforced by the schema's own UNIQUE constraint.
//
// Negative control: with `identifier TEXT NOT NULL UNIQUE` in
// migrations/0001_initial_schema.sql changed to drop UNIQUE, this test was
// run and failed to observe an error — verified by hand, restored before
// committing.
func TestUserStore_CreateUser_DuplicateIdentifierFails(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	store := NewUserStore(pool)

	if _, err := store.CreateUser(ctx, SeedUser{Identifier: "dup@example.com", PasswordHash: testPasswordHash, Role: "user"}); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	if _, err := store.CreateUser(ctx, SeedUser{Identifier: "dup@example.com", PasswordHash: testPasswordHash, Role: "user"}); err == nil {
		t.Fatal("second CreateUser with the same identifier succeeded; want the schema's UNIQUE constraint to refuse it (RS-35)")
	}
}
