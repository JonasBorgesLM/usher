// Command seed creates one known user per role, for local runs
// (REQUIREMENTS §1.1: no user management UI or API is a deliberate non-goal,
// so this is the only way a local database gets a user to log in as).
//
// It is idempotent: running it against an already-seeded database reports
// each existing user and creates nothing new.
//
// Passwords are NOT yet functional. Argon2id hashing (RS-13) is issue #14;
// until it lands, every seeded user's password_hash is a clearly-marked
// placeholder that cannot be produced by hashing any real password, and no
// login attempt can succeed against it. This command exists now because the
// user store (#13) needs fixture data to be tested against, independent of
// whether hashing exists yet.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JonasBorgesLM/usher/internal/config"
	"github.com/JonasBorgesLM/usher/internal/store/postgres"
)

// placeholderHash is deliberately not a real Argon2id hash of anything — its
// shape is PHC-like only so it satisfies the schema's length check, not so
// it looks usable. #14 replaces every reference to this constant.
const placeholderHash = "$argon2id$v=19$m=65536,t=3,p=4$c2VlZC1wbGFjZWhvbGRlcg$bm90LWEtcmVhbC1oYXNoLXlldA" // #nosec G101 -- explicitly not a credential; see doc comment above

// seedUsers is provisional: REQUIREMENTS RF-05 says permission is the
// intersection of client scope and role, but the role vocabulary itself is
// M5's design. "admin" and "user" are the two placeholders that let the
// store and RBAC work be tested before that vocabulary exists.
var seedUsers = []postgres.SeedUser{
	{Identifier: "admin@example.com", PasswordHash: placeholderHash, Role: "admin"},
	{Identifier: "user@example.com", PasswordHash: placeholderHash, Role: "user"},
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
	slog.Warn("passwords are placeholders and cannot be logged in with", "issue", 14)

	for _, u := range seedUsers {
		existing, ok, err := store.ByIdentifier(ctx, u.Identifier)
		if err != nil {
			return fmt.Errorf("check for existing user %s: %w", u.Identifier, err)
		}
		if ok {
			slog.Info("already exists, skipping", "identifier", u.Identifier, "id", existing.ID, "role", existing.Role)
			continue
		}
		id, err := store.CreateUser(ctx, u)
		if err != nil {
			return fmt.Errorf("create user %s: %w", u.Identifier, err)
		}
		slog.Info("created", "identifier", u.Identifier, "id", id, "role", u.Role)
	}
	return nil
}
