// Package oauth holds the OAuth protocol's own state — authorization codes,
// refresh token families, consent, and the shape of a /token response. It
// imports nothing under internal/proxy, and nothing under internal/proxy
// imports it (ADR-0001): the protocol does not know a gateway forwards its
// tokens, and the gateway validates tokens through pkg/tokenvalidator, never
// by reaching into these types.
package oauth

import (
	"context"
	"errors"
	"time"
)

// Code is a pending authorization code, alive for at most RF-12's bound.
type Code struct {
	Value         string // opaque, ≥128 bits from crypto/rand
	ClientID      string
	RedirectURI   string // exact string this code was issued for (RS-02)
	CodeChallenge string // S256 only (RS-01)
	Nonce         string // "" if the request carried none (RS-30)
	Scope         []string
	Subject       string
	ExpiresAt     time.Time
}

// ErrCodeExists reports that Save's value collides with a live code — the
// caller must draw a fresh value from crypto/rand, never overwrite one.
var ErrCodeExists = errors.New("oauth: code already exists")

// ErrCodeNotFound reports that a code was never issued, already consumed,
// or expired — CodeStore.Consume does not distinguish the three (RS-25).
var ErrCodeNotFound = errors.New("oauth: code not found")

// CodeStore persists pending codes and their post-consumption tombstones.
// Redis-backed (REQUIREMENTS §7.1), implemented in internal/store/redis.
type CodeStore interface {
	Save(ctx context.Context, c Code) error

	// Consume atomically deletes and returns c, or ErrCodeNotFound. One
	// round trip (GETDEL or a Lua script) — RS-04's negative control is a
	// store that GETs then DELs, which lets two concurrent callers both
	// succeed.
	Consume(ctx context.Context, value string) (Code, error)

	// Tombstone records that value produced familyID, kept for ttl (the
	// access token's maximum lifetime, RF-12). Called after issuance
	// succeeds, so RS-04's replay-revokes-everything window opens as late
	// as possible.
	//
	// Residual, stated rather than hidden: a crash between a successful
	// Consume and this call leaves that one code's replay undetectable —
	// docs/ARCHITECTURE.md §13 names this explicitly.
	Tombstone(ctx context.Context, value, familyID string, ttl time.Duration) error

	// TombstonedFamily reports the family value produced, if its tombstone
	// is still live. Called when Consume fails, to tell "replay of a code
	// that succeeded once" (revoke) from "never existed or expired"
	// (ordinary invalid_grant).
	TombstonedFamily(ctx context.Context, value string) (familyID string, found bool, err error)
}

// Family is one refresh-token lineage. RevokedReason is set by whichever of
// RF-06 (client or admin), RF-13 (consent revoked) or RS-11 (reuse) revoked
// it — ADR-0017 records the reason on this row precisely so that fact
// survives independent of the audit stream reaching crier.
type Family struct {
	ID            string
	ClientID      string // RS-34: rotation requires the same client
	Subject       string
	Scope         []string // RS-34: a later request may only narrow this
	CreatedAt     time.Time
	ExpiresAt     time.Time // absolute lifetime (RF-12)
	RevokedAt     *time.Time
	RevokedReason string // "", "reuse_detected", "revoked_by_client", "admin", "consent_revoked"
}

// RefreshToken is one issued token in a family. The raw value is never
// stored (RS-10) — only its hash.
type RefreshToken struct {
	FamilyID   string
	Hash       [32]byte // SHA-256 of the opaque token
	IssuedAt   time.Time
	ExpiresAt  time.Time // idle lifetime (RF-12)
	ConsumedAt *time.Time
}

// ErrRefreshTokenNotFound reports that Lookup's hash matches no row, or
// matches one whose idle (RefreshToken.ExpiresAt) or absolute
// (Family.ExpiresAt) lifetime has already passed — indistinguishably, the
// same ambiguity ErrCodeNotFound already gives a consumed-or-expired code.
// A family that exists, is unexpired, but has RevokedAt set is NOT folded
// in here: Lookup returns it as-is, so a caller deciding what revocation
// means (reuse detection, administrative revocation) can see it.
var ErrRefreshTokenNotFound = errors.New("oauth: refresh token not found")

// FamilyStore is Postgres-backed (ADR-0002: losing it makes reuse detection
// fail silently, which is worse than not detecting it).
type FamilyStore interface {
	CreateFamily(ctx context.Context, f Family, first RefreshToken) error

	// Rotate is RS-11's atomic compare-and-set: if hash is unconsumed, mark
	// it consumed and insert next in the SAME statement, returning
	// (true, nil). If hash was already consumed, insert nothing and return
	// (false, nil) — the caller treats false as reuse (ADR-0012: no grace
	// window) and revokes in the same request. This must be one conditional
	// UPDATE; a SELECT followed by an UPDATE is the race RS-11 forbids.
	Rotate(ctx context.Context, hash [32]byte, next RefreshToken) (consumed bool, err error)

	// Revoke sets RevokedAt/RevokedReason idempotently.
	Revoke(ctx context.Context, familyID, reason string) error

	// RevokeAllForSubject is administrative revocation (RF-06) and, scoped
	// by the caller to one client's families, consent revocation (RF-13).
	RevokeAllForSubject(ctx context.Context, subject, reason string) error

	// Lookup finds the family and token owning hash, for RS-34's binding
	// checks before Rotate is attempted.
	Lookup(ctx context.Context, hash [32]byte) (Family, RefreshToken, error)
}

// ConsentStore is Postgres-backed, auditable (REQUIREMENTS §7.1).
type ConsentStore interface {
	// Granted reports the scopes previously granted, or ok=false if none —
	// never an error for "no consent yet".
	Granted(ctx context.Context, subject, clientID string) (scope []string, ok bool, err error)

	// Grant replaces any prior grant for the pair with scope. A request for
	// a scope outside the prior grant re-prompts and then calls this with
	// the union (RF-13) — Grant itself does not union; the caller decides
	// what "the new grant" is.
	Grant(ctx context.Context, subject, clientID string, scope []string) error

	Revoke(ctx context.Context, subject, clientID string) error
}

// TokenResponse is what POST /token serializes on success (RF-03).
type TokenResponse struct {
	AccessToken  string
	RefreshToken string // "" when this grant does not rotate one
	IDToken      string // "" unless the grant's scope included openid
	TokenType    string // always "Bearer"
	ExpiresIn    int
	Scope        string
}
