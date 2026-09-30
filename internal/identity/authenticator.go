package identity

import (
	"context"
	"errors"
	"fmt"
)

// ErrLoginFailed is the one error every failed login attempt returns —
// wrong password, unknown identifier, or a mismatch, all collapsed into the
// same value (RS-14's message symmetry, RS-25: ambiguity here is a
// security property, not a lack of clarity). A caller that needs to log
// *why* a login failed does so from context it already has (the identifier
// it looked up), never by inspecting this error.
var ErrLoginFailed = errors.New("identity: login failed")

// ErrRateLimited reports that the account axis (RS-22) denied this attempt.
// Distinguishable from ErrLoginFailed on purpose: a caller maps it to a
// different response (429, not 401), the same way ErrSaturated and a store
// error already stay distinguishable below. It carries no account-existence
// information, because the check that produces it runs identically for
// existing and non-existent identifiers — see AccountRateLimiter below.
var ErrRateLimited = errors.New("identity: rate limited")

// AccountRateLimiter is the account axis of RS-22, narrowed to what
// Authenticator needs. *moat/ratelimit.Limiter satisfies it.
type AccountRateLimiter interface {
	// Allow reports whether an attempt for key may proceed, consuming one
	// unit of its allowance if so. A limiter built with moat's default
	// FailClosed policy returns false on its own store's error — RNF-04's
	// "infrastructure failure denies" arrives through this return value,
	// not through a separate error Authenticator has to interpret.
	Allow(ctx context.Context, key string) bool
}

// AuthenticatorOption configures an Authenticator at construction.
type AuthenticatorOption func(*Authenticator)

// WithAccountLimiter enables the account axis (RS-22). Without it,
// Authenticator enforces none — the zero value has no limiter, which a
// caller composing the IP axis separately (REQUIREMENTS §7.2) may prefer
// until both are wired together.
func WithAccountLimiter(limiter AccountRateLimiter) AuthenticatorOption {
	return func(a *Authenticator) { a.limiter = limiter }
}

// LoginResult is what a successful Attempt returns.
type LoginResult struct {
	User User
}

// dummyPassword is never compared against anything — Authenticator only
// ever hashes it once, at construction, to produce a dummy hash of the
// right shape for the non-existent-identifier path.
const dummyPassword = "identity-dummy-password-never-matches-anything"

// Authenticator runs constant-work login (RS-14, T-10): the underlying
// Hasher.Verify call happens exactly once per Attempt, whether or not the
// identifier resolves to a real user, against either that user's stored
// hash or a fixed dummy hash — computed once, here, at construction, with
// current parameters, so the non-existent path costs what the existing
// path costs and never differs by "freshly hashing a dummy value now."
type Authenticator struct {
	store     UserStore
	hasher    *Hasher
	dummyHash string
	limiter   AccountRateLimiter // nil unless WithAccountLimiter is passed
}

// NewAuthenticator computes its dummy hash once, under params — callers
// pass the same Params their Hasher was built with, so neither path is
// distinguishable by cost.
func NewAuthenticator(store UserStore, hasher *Hasher, params Params, opts ...AuthenticatorOption) (*Authenticator, error) {
	dummyHash, err := HashPassword(dummyPassword, params)
	if err != nil {
		return nil, fmt.Errorf("identity: compute dummy hash: %w", err)
	}
	a := &Authenticator{store: store, hasher: hasher, dummyHash: dummyHash}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Attempt canonicalizes identifier (RS-35), checks the account axis if one
// is configured (RS-22), looks the identifier up, then calls Verify exactly
// once — against the resolved user's hash if found, the fixed dummy hash
// otherwise — and returns LoginResult on success or ErrLoginFailed on any
// kind of failure.
//
// An error from the lookup itself, or from Hasher (ErrSaturated, a canceled
// context), propagates unwrapped: those are infrastructure signals a
// caller maps to 503 or similar, never confused with ErrLoginFailed's
// "these credentials do not work" (RF-06's error taxonomy depends on
// telling the two apart).
//
// Rehashing a record found to need one (ADR-0005) is deliberately not
// this function's job — it is the caller's, once Attempt reports success,
// exactly as internal/store/postgres's own rehash-flow test already
// proves the sequence (VerifyPassword, NeedsRehash, HashPassword,
// UpdateHash) composes.
func (a *Authenticator) Attempt(ctx context.Context, identifier, password string) (LoginResult, error) {
	canonical := CanonicalizeIdentifier(identifier)

	// Checked before the lookup, on the canonical identifier, so an
	// existing and a non-existent account are charged identically (RS-14
	// extended to this axis) — the limiter cannot see which one it is
	// guarding, because Attempt has not looked yet.
	if a.limiter != nil && !a.limiter.Allow(ctx, canonical) {
		return LoginResult{}, ErrRateLimited
	}

	u, ok, err := a.store.ByIdentifier(ctx, canonical)
	if err != nil {
		return LoginResult{}, fmt.Errorf("identity: look up identifier: %w", err)
	}

	encoded := a.dummyHash
	if ok {
		encoded = u.PasswordHash
	}

	valid, err := a.hasher.Verify(ctx, password, encoded)
	if err != nil {
		return LoginResult{}, err
	}
	if !ok || !valid {
		return LoginResult{}, ErrLoginFailed
	}
	return LoginResult{User: u}, nil
}
