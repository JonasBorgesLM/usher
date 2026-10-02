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
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
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
	msg, err := jws.Parse([]byte(raw))
	if err != nil {
		return Claims{}, fmt.Errorf("%w: parse: %w", ErrMalformedToken, err)
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return Claims{}, fmt.Errorf("%w: %d signatures, want exactly 1", ErrMalformedToken, len(sigs))
	}
	hdrs := sigs[0].ProtectedHeaders()

	kid, ok := hdrs.KeyID()
	if !ok || kid == "" {
		return Claims{}, fmt.Errorf("%w: no kid in the protected header", ErrMalformedToken)
	}

	typ, ok := hdrs.Type()
	if !ok || typ != "at+jwt" {
		return Claims{}, fmt.Errorf("%w: typ = %q, want %q", ErrWrongTokenType, typ, "at+jwt")
	}

	pub, registeredAlg, err := v.source.Key(ctx, kid)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: resolve kid %q: %w", ErrMalformedToken, kid, err)
	}
	if !slices.Contains(v.allowed, registeredAlg) {
		return Claims{}, fmt.Errorf("%w: kid %q is registered under %q, not in this validator's allow-list",
			ErrAlgorithmNotAllowed, kid, registeredAlg)
	}
	jwaAlg, err := signatureAlgorithm(registeredAlg)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrAlgorithmNotAllowed, err)
	}

	token, err := jwt.Parse([]byte(raw),
		jwt.WithKey(jwaAlg, pub),
		jwt.WithContext(ctx),
		jwt.WithIssuer(v.cfg.issuer),
		jwt.WithAudience(wantAudience),
		jwt.WithAcceptableSkew(v.cfg.clockSkew),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithRequiredClaim(jwt.NotBeforeKey),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.JwtIDKey),
		jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithRequiredClaim("client_id"),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrClaimsInvalid, err)
	}

	return claimsFromToken(token)
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
