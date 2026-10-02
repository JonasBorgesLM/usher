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
// server, through NewJWKSSource over HTTP. A third, narrower one was added
// in #38: the AS's own /revoke handler (cmd/usher), through
// ValidateForRevocation — it needs the same signature verification
// ValidateAccessToken already does, minus the audience check a resource
// server's own caller needs and a /revoke caller does not have.
package tokenvalidator

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/JonasBorgesLM/moat/ratelimit"
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
	clock     func() time.Time
}

// Option configures a Validator at construction.
type Option func(*config)

// WithClockSkew sets the leeway applied to exp/nbf/iat (RS-07), measured in
// seconds — never in minutes.
func WithClockSkew(d time.Duration) Option {
	return func(c *config) { c.clockSkew = d }
}

// WithClock overrides what "now" means for exp/nbf/iat validation —
// internal/keys.Load's own WithClock (#32) found the same gap first: a
// caller that issues and validates within the same process over an
// injected, non-real clock (as cmd/usher's own test fixtures do) needs
// validation to agree with issuance, which jwx's own default (the real
// system clock) cannot. A nil now (the default) keeps jwx's own real-time
// behavior unchanged.
func WithClock(now func() time.Time) Option {
	return func(c *config) { c.clock = now }
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

// ErrMalformedToken reports that raw is not a single-signature compact JWS,
// or that its protected header is missing kid (RS-09: every JWT carries
// one) or carries no kid resolvable against source.
var ErrMalformedToken = errors.New("tokenvalidator: malformed token")

// ErrWrongTokenType reports that the protected header's typ does not match
// what this operation requires (RS-08).
var ErrWrongTokenType = errors.New("tokenvalidator: wrong token type")

// ErrAlgorithmNotAllowed reports that the key source's registered algorithm
// for this kid is not in the allow-list New was built with (RS-06).
var ErrAlgorithmNotAllowed = errors.New("tokenvalidator: algorithm not allowed")

// ErrClaimsInvalid reports that the signature verified but a claim failed
// — expired, not yet valid, wrong iss/aud, or a required claim absent
// (RS-07). The wrapped error is jwt.Validate's own, which errors.AsType can
// recover structured detail from.
var ErrClaimsInvalid = errors.New("tokenvalidator: claims invalid")

// ValidateAccessToken checks the allow-list, the full claim set, typ ==
// "at+jwt" (RFC 9068) and that Audience contains wantAudience (RS-19). An ID
// token presented here fails on typ (RS-08) — checked as well as aud, so
// neither claim alone is the one misconfiguration away from accepting the
// other token type.
//
// RS-06's own point is structural here, not a check that could be skipped:
// the verification algorithm comes only from source.Key's own registered
// Algorithm for this kid (itself fixed by configuration — internal/keys'
// loader, never request input), passed explicitly to jws's verifier. The
// token's own protected header "alg" is never read for that decision; jws
// additionally refuses outright whenever that header disagrees with the
// algorithm actually used to verify (jws.Verify's own documented default),
// so a forged header naming a different algorithm than the one the kid is
// registered under is rejected before any claim is even inspected — this
// is what makes an RS256-key-as-HS256-secret downgrade and alg:none both
// fail the same way, by construction, rather than by a check this function
// could get backwards.
func (v *Validator) ValidateAccessToken(ctx context.Context, raw, wantAudience string) (Claims, error) {
	token, err := v.verify(ctx, raw, wantAudience)
	if err != nil {
		return Claims{}, err
	}
	return claimsFromToken(token)
}

// ValidateForRevocation checks the same algorithm allow-list (RS-06), typ
// == "at+jwt" (RS-08) and claim set (RS-07) ValidateAccessToken does,
// except the audience: /revoke's only caller is the client the token was
// issued to (RFC 7009 §2.1), not a resource server enforcing RS-19 for one
// particular audience, so there is no single wantAudience to require
// here. The caller compares the returned Claims.ClientID against its own
// authenticated client instead — that comparison is RFC 7009's own
// binding check, not this package's.
func (v *Validator) ValidateForRevocation(ctx context.Context, raw string) (Claims, error) {
	token, err := v.verify(ctx, raw, "")
	if err != nil {
		return Claims{}, err
	}
	return claimsFromToken(token)
}

// verify is ValidateAccessToken and ValidateForRevocation's shared core —
// kid/typ extraction, the allow-list check (RS-06), and the claim set
// (RS-07), with the audience check applied only when wantAudience is
// non-empty, the one claim whose requirement differs between the two
// callers.
func (v *Validator) verify(ctx context.Context, raw, wantAudience string) (jwt.Token, error) {
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrMalformedToken, err)
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return nil, fmt.Errorf("%w: %d signatures, want exactly 1", ErrMalformedToken, len(sigs))
	}
	hdrs := sigs[0].ProtectedHeaders()

	kid, ok := hdrs.KeyID()
	if !ok || kid == "" {
		return nil, fmt.Errorf("%w: no kid in the protected header", ErrMalformedToken)
	}

	typ, ok := hdrs.Type()
	if !ok || typ != "at+jwt" {
		return nil, fmt.Errorf("%w: typ = %q, want %q", ErrWrongTokenType, typ, "at+jwt")
	}

	pub, registeredAlg, err := v.source.Key(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve kid %q: %w", ErrMalformedToken, kid, err)
	}
	if !slices.Contains(v.allowed, registeredAlg) {
		return nil, fmt.Errorf("%w: kid %q is registered under %q, not in this validator's allow-list",
			ErrAlgorithmNotAllowed, kid, registeredAlg)
	}
	jwaAlg, err := signatureAlgorithm(registeredAlg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAlgorithmNotAllowed, err)
	}

	opts := []jwt.ParseOption{
		jwt.WithKey(jwaAlg, pub),
		jwt.WithContext(ctx),
		jwt.WithIssuer(v.cfg.issuer),
		jwt.WithAcceptableSkew(v.cfg.clockSkew),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithRequiredClaim(jwt.NotBeforeKey),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.JwtIDKey),
		jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithRequiredClaim("client_id"),
	}
	if wantAudience != "" {
		opts = append(opts, jwt.WithAudience(wantAudience))
	}
	if v.cfg.clock != nil {
		opts = append(opts, jwt.WithClock(jwt.ClockFunc(v.cfg.clock)))
	}

	token, err := jwt.Parse([]byte(raw), opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClaimsInvalid, err)
	}
	return token, nil
}

// signatureAlgorithm maps a KeySource's registered Algorithm to the
// jwa.SignatureAlgorithm jws verifies with. The two are the same two names
// (RS-06's whole allow-list), kept as distinct types so this package's own
// public surface (Algorithm) never forces a caller implementing KeySource
// to import jwx/v4/jwa.
func signatureAlgorithm(a Algorithm) (jwa.SignatureAlgorithm, error) {
	switch a {
	case RS256:
		return jwa.RS256(), nil
	case ES256:
		return jwa.ES256(), nil
	default:
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("unsupported algorithm %q", a)
	}
}

// claimsFromToken reads Claims out of an already verified-and-validated
// jwt.Token. Every field it reads was required present by ValidateAccessToken's
// own jwt.WithRequiredClaim calls, except scope (RFC 9068 leaves it
// optional).
func claimsFromToken(token jwt.Token) (Claims, error) {
	sub, _ := token.Subject()
	aud, _ := token.Audience()
	exp, _ := token.Expiration()
	iat, _ := token.IssuedAt()
	jti, _ := token.JwtID()
	clientID, err := jwt.Get[string](token, "client_id")
	if err != nil {
		return Claims{}, fmt.Errorf("%w: client_id: %w", ErrClaimsInvalid, err)
	}

	var scope []string
	if raw, scopeErr := jwt.Get[string](token, "scope"); scopeErr == nil && raw != "" {
		scope = strings.Fields(raw)
	}

	return Claims{
		Subject:   sub,
		ClientID:  clientID,
		Audience:  aud,
		Scope:     scope,
		IssuedAt:  iat,
		ExpiresAt: exp,
		JTI:       jti,
	}, nil
}

// ValidateIDToken checks the same claim set with typ == "id_token" and
// Audience == {clientID}. Never accepted where ValidateAccessToken is
// required.
//
// Implemented in M7 (REQUIREMENTS §11).
func (v *Validator) ValidateIDToken(ctx context.Context, raw, clientID string) (Claims, error) {
	panic("tokenvalidator: ValidateIDToken not implemented (M7)")
}

// ErrUnknownKID reports that no key in the most recently fetched JWKS
// matches the requested kid — whether that document has ever been fetched
// at all, a kid that never existed, or one that retired before this
// source's cache last refreshed, indistinguishably (the same ambiguity
// RS-25 already asks of invalid_grant, here applied to key lookup).
var ErrUnknownKID = errors.New("tokenvalidator: no key matches the requested kid")

// ErrRefetchRateLimited reports that this source already attempted
// refetchLimit fetches within refetchWindow, and refuses to attempt
// another — RS-09's own point: without this, a flood of tokens bearing
// random, never-valid kid values would turn every lookup miss into an
// outbound HTTP call, turning the resource server into a DoS amplifier
// against the AS (T-15).
var ErrRefetchRateLimited = errors.New("tokenvalidator: JWKS refetch rate limit exceeded")

// maxJWKSResponseBytes bounds how much of a JWKS response this source will
// read — a real keyset is a handful of keys, comfortably under this; a
// response that large is either misconfigured or hostile, either way not
// worth holding entirely in memory to find out.
const maxJWKSResponseBytes = 1 << 20 // 1 MiB

// refetchLimiterKey is the single, constant key every call shares against
// the rate limiter below. Keying by kid instead would defeat the limit
// entirely: the attack this guards against is a flood of distinct,
// never-valid kid values, each of which would get its own fresh bucket.
const refetchLimiterKey = "jwks-refetch"

// JWKSSource is a KeySource backed by a remote JWKS document, with
// rate-limited refetch on an unknown kid (RS-09) — the limit that keeps a
// flood of forged-kid tokens from turning the resource server into a DoS
// amplifier against the AS. There is no separate, time-based cache
// refresh: the cache is replaced only by a fetch a kid miss triggered,
// which is what lets a newly published key be picked up without a
// restart — the stated, deliberate scope of this phase (REQUIREMENTS
// §11, M3). A key already in the cache is served from it indefinitely
// until some other kid miss happens to trigger a refetch that drops it;
// RS-09's own residual ("a consumer validating directly keeps accepting
// a key until its own JWKS cache expires") already covers the gap this
// leaves.
type JWKSSource struct {
	url           string
	client        *http.Client
	refetchLimit  int
	refetchWindow time.Duration
	limiter       *ratelimit.Limiter

	mu     sync.RWMutex
	cached jwk.Set // nil until the first successful fetch
}

// NewJWKSSource builds a JWKSSource. refetchLimit fetches are allowed as
// an immediate burst, refilling continuously at refetchLimit per
// refetchWindow — moat/ratelimit's own token-bucket algorithm, the same
// one already governing every other rate limit in this project (RS-22),
// chosen there and here because a fixed window permits up to twice the
// intended rate across its own boundary.
func NewJWKSSource(jwksURL string, httpClient *http.Client, refetchLimit int, refetchWindow time.Duration) *JWKSSource {
	perSecond := float64(refetchLimit) / refetchWindow.Seconds()
	return &JWKSSource{
		url: jwksURL, client: httpClient,
		refetchLimit: refetchLimit, refetchWindow: refetchWindow,
		limiter: ratelimit.New(refetchLimit, perSecond),
	}
}

// Key implements KeySource: a cache hit returns immediately; a miss
// spends one of this source's rate-limited refetch attempts, then tries
// the lookup again against whatever the fetch returned.
func (s *JWKSSource) Key(ctx context.Context, kid string) (crypto.PublicKey, Algorithm, error) {
	if pub, alg, found := s.lookup(kid); found {
		return pub, alg, nil
	}

	if !s.limiter.Allow(ctx, refetchLimiterKey) {
		return nil, "", ErrRefetchRateLimited
	}
	if err := s.fetch(ctx); err != nil {
		return nil, "", fmt.Errorf("tokenvalidator: fetch JWKS: %w", err)
	}

	pub, alg, found := s.lookup(kid)
	if !found {
		return nil, "", ErrUnknownKID
	}
	return pub, alg, nil
}

// lookup answers kid against the cache alone, taking no lock longer than
// reading it requires and never reaching the network.
func (s *JWKSSource) lookup(kid string) (crypto.PublicKey, Algorithm, bool) {
	s.mu.RLock()
	cached := s.cached
	s.mu.RUnlock()
	if cached == nil {
		return nil, "", false
	}
	key, ok := cached.LookupKeyID(kid)
	if !ok {
		return nil, "", false
	}
	pub, err := jwk.Export[any](key)
	if err != nil {
		return nil, "", false
	}
	alg, ok := key.Algorithm()
	if !ok {
		return nil, "", false
	}
	return pub, Algorithm(alg.String()), true
}

// fetch replaces the cache with a freshly retrieved JWKS document. It
// never partially updates the cache: a failed or malformed fetch leaves
// whatever was cached before untouched, so a transient error at the AS
// cannot turn into every key becoming unresolvable.
func (s *JWKSSource) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable; the read below already surfaces a torn response

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseBytes))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	s.mu.Lock()
	s.cached = set
	s.mu.Unlock()
	return nil
}
