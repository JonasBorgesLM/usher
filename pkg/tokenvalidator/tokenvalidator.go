// Package tokenvalidator validates JWTs against a fixed algorithm allow-list
// and a full claim set (REQUIREMENTS RS-06, RS-07). The allow-list is fixed
// at construction — a token's own alg header never selects the verification
// method.
//
// It imports nothing under internal/. This package is the candidate moat
// might one day extract as its own jwtauth module, and REQUIREMENTS §7.4
// records its exported signature changes at the end of every phase for that
// reason (ADR-0009) — moving a type from internal/ into this package's
// public surface would make that measurement mean something else.
//
// Two consumers exist in this repository: the gateway, through an
// in-process keys.Keyset (via Keyset.AsKeySource), and the demo resource
// server, through NewJWKSSource over HTTP.
package tokenvalidator

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"time"
)

// Algorithm is a signature algorithm a Validator's allow-list accepts
// (RS-06).
type Algorithm string

// The two algorithms REQUIREMENTS RS-06 permits. RS256 is the default for
// newly issued keys (ADR-0015 amendment); ES256 keys may still be present in
// a keyset.
const (
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
)

// KeySource resolves a kid to a verification key and the algorithm it was
// registered under. keys.Keyset satisfies it for the gateway; NewJWKSSource
// satisfies it for the demo resource server and any external consumer.
type KeySource interface {
	Key(ctx context.Context, kid string) (crypto.PublicKey, Algorithm, error)
}

// ErrNoAllowedAlgorithms reports that New was called with an empty
// algorithm allow-list — a construction error, not a validator that rejects
// everything silently.
var ErrNoAllowedAlgorithms = errors.New("tokenvalidator: allowed must be non-empty")

type config struct {
	clockSkew time.Duration
	issuer    string
}

// Option configures a Validator at construction.
type Option func(*config)

// WithClockSkew sets the leeway applied to exp/nbf/iat (RS-07), measured in
// seconds — never in minutes.
func WithClockSkew(d time.Duration) Option {
	return func(c *config) { c.clockSkew = d }
}

// WithIssuer requires an exact iss match.
func WithIssuer(iss string) Option {
	return func(c *config) { c.issuer = iss }
}

// Validator checks a JWT's signature against a fixed algorithm allow-list
// (RS-06) and a full claim set (RS-07).
type Validator struct {
	source  KeySource
	allowed []Algorithm
	cfg     config
}

// New builds a Validator. It fails with ErrNoAllowedAlgorithms when allowed
// is empty.
func New(source KeySource, allowed []Algorithm, opts ...Option) (*Validator, error) {
	if len(allowed) == 0 {
		return nil, ErrNoAllowedAlgorithms
	}
	cfg := config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Validator{source: source, allowed: allowed, cfg: cfg}, nil
}

// Claims is populated only once every check in ValidateAccessToken or
// ValidateIDToken has passed.
type Claims struct {
	Subject   string
	ClientID  string
	Audience  []string
	Scope     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	JTI       string
}

// ValidateAccessToken checks the allow-list, the full claim set, typ ==
// "at+jwt" (RFC 9068) and that Audience contains wantAudience (RS-19). An ID
// token presented here fails on typ (RS-08) — checked as well as aud, so
// neither claim alone is the one misconfiguration away from accepting the
// other token type.
//
// Implemented in M2 (REQUIREMENTS §11); this stub panics if called, so a
// caller cannot mistake "not implemented" for "always valid."
func (v *Validator) ValidateAccessToken(ctx context.Context, raw, wantAudience string) (Claims, error) {
	panic("tokenvalidator: ValidateAccessToken not implemented (M2)")
}

// ValidateIDToken checks the same claim set with typ == "id_token" and
// Audience == {clientID}. Never accepted where ValidateAccessToken is
// required.
//
// Implemented in M7 (REQUIREMENTS §11).
func (v *Validator) ValidateIDToken(ctx context.Context, raw, clientID string) (Claims, error) {
	panic("tokenvalidator: ValidateIDToken not implemented (M7)")
}

// JWKSSource is a KeySource backed by a remote JWKS document, with
// rate-limited refetch on an unknown kid (RS-09) — the limit that keeps a
// flood of forged-kid tokens from turning the resource server into a DoS
// amplifier against the AS.
type JWKSSource struct {
	url           string
	client        *http.Client
	refetchLimit  int
	refetchWindow time.Duration
}

// NewJWKSSource builds a JWKSSource. Fetching and caching are implemented in
// M3 (REQUIREMENTS §11).
func NewJWKSSource(jwksURL string, httpClient *http.Client, refetchLimit int, refetchWindow time.Duration) *JWKSSource {
	return &JWKSSource{url: jwksURL, client: httpClient, refetchLimit: refetchLimit, refetchWindow: refetchWindow}
}

// Key implements KeySource. Implemented in M3.
func (s *JWKSSource) Key(ctx context.Context, kid string) (crypto.PublicKey, Algorithm, error) {
	panic("tokenvalidator: JWKSSource.Key not implemented (M3)")
}
