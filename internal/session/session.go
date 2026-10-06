// Package session holds the two kinds of server-side state /authorize
// depends on: the opaque, single-use login/consent Challenge (RS-05), and
// the AS's own BrowserSession (RF-10, RS-31) — distinct from any OAuth
// client's session and from the OAuth flow's Code. Both are Redis-backed,
// implemented in internal/store/redis.
package session

import (
	"context"
	"errors"
	"time"
)

// Challenge is one pending /authorize flow, addressed by an opaque id that
// carries no request parameters (RS-05).
type Challenge struct {
	ID            string
	ClientID      string
	RedirectURI   string
	Scope         []string
	State         string
	CodeChallenge string
	Nonce         string         // "" if the request carried none (RS-30)
	Prompt        string         // "", "none" or "login" -- /authorize already rejects anything else (RF-11)
	MaxAge        *time.Duration // nil if the request carried none (RF-11)
	Subject       string         // "" until login succeeds
	AuthTime      time.Time      // set together with Subject (ADR-0020); zero until then
	ExpiresAt     time.Time
}

// ErrChallengeNotFound reports that no live challenge matches — expired,
// never issued, or already consumed (RS-05: single-use).
var ErrChallengeNotFound = errors.New("session: challenge not found")

// ChallengeStore is Redis-backed (ephemeral, REQUIREMENTS §7.1).
type ChallengeStore interface {
	Save(ctx context.Context, c Challenge) error

	// Get reads without consuming — /login and /consent each render the
	// same challenge across a GET/POST pair before the flow completes.
	Get(ctx context.Context, id string) (Challenge, error)

	// SetAuthenticated records the authenticated subject and the moment
	// that authentication happened on a still-pending challenge, between
	// login succeeding (or a prior session being silently reused, ADR-0020)
	// and /consent. authTime becomes the id_token's own auth_time
	// (oauth.Code, RF-11) -- it is the browser session's own AuthTime, not
	// necessarily "now": a silent reuse passes through the session's
	// original login time unchanged, exactly the value RF-11's max_age
	// check at /login already measured it against.
	SetAuthenticated(ctx context.Context, id, subject string, authTime time.Time) error

	// Consume atomically deletes and returns c — single-use (RS-05), the
	// same shape as oauth.CodeStore.Consume. Called once, when /authorize is
	// ready to mint a Code.
	Consume(ctx context.Context, id string) (Challenge, error)
}

// BrowserSession is the AS's own login session, independent of any OAuth
// client's session.
type BrowserSession struct {
	ID        string // opaque, ≥256 bits; stored as its SHA-256 (RS-31)
	Subject   string
	AuthTime  time.Time // RF-11's auth_time, under max_age
	IdleUntil time.Time
	ExpiresAt time.Time // absolute lifetime (RF-12)
}

// ErrSessionNotFound reports that no session matches — absent, or past
// IdleUntil or ExpiresAt.
var ErrSessionNotFound = errors.New("session: browser session not found")

// SessionStore is Redis-backed. Renaming only this one to "Store" would
// break the naming parallel with ChallengeStore in this same package,
// which is why it keeps the stutter instead of "fixing" it.
//
//nolint:revive // the stutter above is intentional, not an oversight
type SessionStore interface {
	Save(ctx context.Context, s BrowserSession) error

	// Get looks up by the SHA-256 of rawID and extends IdleUntil (RF-12).
	Get(ctx context.Context, rawID string) (BrowserSession, error)

	// Delete ends the session server-side. Called before the response that
	// clears the cookie (RS-31) — the order is the requirement, not a
	// suggestion.
	Delete(ctx context.Context, rawID string) error
}
