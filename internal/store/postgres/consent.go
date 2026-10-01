package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JonasBorgesLM/usher/internal/oauth"
)

// ConsentStore implements oauth.ConsentStore over the consent table
// (migrations/0001_initial_schema.sql) — one row per (user_id, client_id),
// matching Grant's own "replaces any prior grant for the pair" contract.
type ConsentStore struct {
	pool *pgxpool.Pool
}

var _ oauth.ConsentStore = (*ConsentStore)(nil)

// NewConsentStore wraps pool. The pool's schema must already be migrated
// (Migrate), the same precondition UserStore states.
func NewConsentStore(pool *pgxpool.Pool) *ConsentStore {
	return &ConsentStore{pool: pool}
}

// Granted implements oauth.ConsentStore. ok=false, never an error, when no
// grant exists yet — RF-13's first-time case is not a failure.
func (s *ConsentStore) Granted(ctx context.Context, subject, clientID string) (scope []string, ok bool, err error) {
	err = s.pool.QueryRow(ctx,
		"SELECT scope FROM consent WHERE user_id = $1 AND client_id = $2",
		subject, clientID,
	).Scan(&scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("postgres: look up consent: %w", err)
	}
	return scope, true, nil
}

// Grant implements oauth.ConsentStore: an upsert, so a second grant for the
// same (subject, clientID) replaces the row rather than accumulating a
// second one — the caller decides what "the new grant" is (the union with
// any prior one, per RF-13), not this method.
func (s *ConsentStore) Grant(ctx context.Context, subject, clientID string, scope []string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO consent (user_id, client_id, scope, granted_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (user_id, client_id) DO UPDATE SET scope = EXCLUDED.scope, granted_at = EXCLUDED.granted_at`,
		subject, clientID, scope,
	)
	if err != nil {
		return fmt.Errorf("postgres: grant consent: %w", err)
	}
	return nil
}

// Revoke implements oauth.ConsentStore. Revoking a grant that does not
// exist is a no-op, not an error — the caller asked for "no consent on
// record," which already holds.
func (s *ConsentStore) Revoke(ctx context.Context, subject, clientID string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM consent WHERE user_id = $1 AND client_id = $2", subject, clientID)
	if err != nil {
		return fmt.Errorf("postgres: revoke consent: %w", err)
	}
	return nil
}
