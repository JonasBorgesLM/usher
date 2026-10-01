// Package identity holds the two things usher calls "who": people (User) who
// authenticate, and registered apps (Client) that request tokens on their
// behalf. Clients are versioned configuration (RF-01), loaded once at
// startup — there is no ClientStore. Users are Postgres-backed through
// UserStore, implemented in internal/store/postgres.
package identity

import (
	"context"
	"errors"
)

// User is a person who can authenticate (RS-13's hash, RF-05's role).
type User struct {
	ID         string
	Identifier string // canonicalized (RS-35) — the form looked up and
	// rate-limited on; two spellings of one identifier is two accounts,
	// not one
	PasswordHash string // PHC string, params versioned (RS-13)
	Role         string
}

// UserStore is Postgres-backed.
type UserStore interface {
	// ByIdentifier looks up by the canonicalized form. ok=false — never an
	// error — when none exists, so RS-14's constant-work login proceeds
	// identically either way.
	ByIdentifier(ctx context.Context, identifier string) (u User, ok bool, err error)

	// UpdateHash rehashes on a successful login against weaker-than-current
	// parameters (RS-13). Never called on a failed attempt.
	UpdateHash(ctx context.Context, userID, newHash string) error
}

// Client is a registered OAuth client (RF-01).
type Client struct {
	ID             string
	Confidential   bool
	SecretHash     string   // SHA-256; "" for a public client (RS-16)
	RedirectURIs   []string // exact strings (RS-02) — no pattern, no prefix
	GrantTypes     []string
	Scopes         []string
	Audiences      []string
	RequireConsent bool
}

// ErrInvalidClientRegistry reports that a client's registration is
// unrepresentable — a relative redirect_uri, one with a fragment, a scheme
// outside the caller's allow-list, or any other shape RF-01 forbids. Load
// callers (internal/config, RNF-05) turn this into a startup refusal, never
// a runtime surprise.
//
// LoadClients and Client.AuthenticateSecret are in client.go.
var ErrInvalidClientRegistry = errors.New("identity: invalid client registry")
