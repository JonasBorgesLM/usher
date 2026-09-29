package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JonasBorgesLM/usher/internal/identity"
)

// UserStore implements identity.UserStore over the users table
// (migrations/0001_initial_schema.sql).
type UserStore struct {
	pool *pgxpool.Pool
}

var _ identity.UserStore = (*UserStore)(nil)

// NewUserStore wraps pool. The pool's schema must already be migrated
// (Migrate) — UserStore does not migrate on its own, so a store used against
// an un-migrated database fails on its first query, not silently.
func NewUserStore(pool *pgxpool.Pool) *UserStore {
	return &UserStore{pool: pool}
}

// ByIdentifier implements identity.UserStore. It returns ok=false, not an
// error, when no row matches — RS-14's constant-work login proceeds
// identically whether the identifier exists or not, and an error return
// here would tempt a caller to branch on it.
func (s *UserStore) ByIdentifier(ctx context.Context, identifier string) (identity.User, bool, error) {
	var u identity.User
	err := s.pool.QueryRow(ctx,
		"SELECT id, identifier, password_hash, role FROM users WHERE identifier = $1",
		identifier,
	).Scan(&u.ID, &u.Identifier, &u.PasswordHash, &u.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, false, nil
	}
	if err != nil {
		return identity.User{}, false, fmt.Errorf("postgres: look up user by identifier: %w", err)
	}
	return u, true, nil
}

// ErrUserNotFound reports that UpdateHash was given a userID with no
// matching row — distinct from ByIdentifier's ok=false, because a rehash is
// only ever attempted right after a successful lookup, so a miss here means
// the row disappeared between the two, not "this is a normal case."
var ErrUserNotFound = errors.New("postgres: user not found")

// UpdateHash implements identity.UserStore.
func (s *UserStore) UpdateHash(ctx context.Context, userID, newHash string) error {
	tag, err := s.pool.Exec(ctx, "UPDATE users SET password_hash = $1 WHERE id = $2", newHash, userID)
	if err != nil {
		return fmt.Errorf("postgres: update password hash: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}
	return nil
}

// SeedUser is one row CreateUser inserts — used by cmd/seed, and by this
// package's own integration tests as fixture data.
type SeedUser struct {
	Identifier   string
	PasswordHash string
	Role         string
}

// CreateUser inserts u and returns its generated id. Exposed for the seed
// command and tests; the protocol paths (login, registration — the latter a
// non-goal per REQUIREMENTS §1.1) do not call it themselves.
func (s *UserStore) CreateUser(ctx context.Context, u SeedUser) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		"INSERT INTO users (identifier, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
		u.Identifier, u.PasswordHash, u.Role,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("postgres: create user: %w", err)
	}
	return id, nil
}
