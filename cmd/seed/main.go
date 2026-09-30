// Command seed creates one known user per role, for local runs
// (REQUIREMENTS §1.1: no user management UI or API is a deliberate non-goal,
// so this is the only way a local database gets a user to log in as).
//
// It is idempotent: running it against an already-seeded database reports
// each existing user and creates nothing new.
//
// Every seeded user shares devPassword, a fixed, clearly-labeled value —
// never anything resembling a real credential, and never used outside a
// local development database.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JonasBorgesLM/usher/internal/config"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/store/postgres"
)

// devPassword is every seeded user's password. Fixed and printed at seed
// time (not secret — there is nothing behind it worth protecting yet, since
// the login endpoint this would authenticate against does not exist until
// #16) so a developer running this command can actually use it.
const devPassword = "usher-local-dev-only" // #nosec G101 -- a fixed local-dev value, not a real credential

// seedRoles is provisional: REQUIREMENTS RF-05 says permission is the
// intersection of client scope and role, but the role vocabulary itself is
// M5's design. "admin" and "user" are the two placeholders that let the
// store and RBAC work be tested before that vocabulary exists.
var seedRoles = []struct {
	identifier string
	role       string
}{
	{"admin@example.com", "admin"},
	{"user@example.com", "user"},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(config.FromOSEnv)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect to Postgres: %w", err)
	}
	defer pool.Close()

	if err := postgres.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	store := postgres.NewUserStore(pool)
	slog.Warn("every seeded user shares one fixed password; local development only", "password", devPassword)

	for _, seed := range seedRoles {
		// Canonicalized once, here, at creation (RS-35) — Authenticator
		// canonicalizes again at lookup, so a stored identifier that was
		// not already canonical would never match a real login attempt.
		canonical := identity.CanonicalizeIdentifier(seed.identifier)

		existing, ok, err := store.ByIdentifier(ctx, canonical)
		if err != nil {
			return fmt.Errorf("check for existing user %s: %w", canonical, err)
		}
		if ok {
			slog.Info("already exists, skipping", "identifier", canonical, "id", existing.ID, "role", existing.Role)
			continue
		}

		hash, err := identity.HashPassword(devPassword, identity.DefaultParams)
		if err != nil {
			return fmt.Errorf("hash password for %s: %w", canonical, err)
		}
		id, err := store.CreateUser(ctx, postgres.SeedUser{Identifier: canonical, PasswordHash: hash, Role: seed.role})
		if err != nil {
			return fmt.Errorf("create user %s: %w", canonical, err)
		}
		slog.Info("created", "identifier", canonical, "id", id, "role", seed.role)
	}
	return nil
}
