# `pkg/tokenvalidator` — exported API log

**Why this file exists:** `moat` declined to extract a `jwtauth` module and
recorded a reopening criterion — the signature must stabilize under real use,
measured by how often it changes across a consumer's iterations, and informed
by a second consumer. This project produces that measurement (ADR-0009). At
the end of every phase, that phase's closing PR appends a row: what changed in
`pkg/tokenvalidator`'s exported surface, and which consumer drove it.

**How a row is produced:** `go doc -all ./pkg/tokenvalidator`, diffed against
the previous row, under the Go version pinned for lint in CI
(`LINT_GO_VERSION` in `.github/workflows/ci.yml`) — golangci-lint's own
toolchain constraint means that is also the version this log should be
generated under, so a contributor reproducing a row gets the same output CI
would.

---

## M0 — Foundations (skeleton, issue #7)

**Consumer driving this entry:** none yet — this is the first entry, the
skeleton `docs/ARCHITECTURE.md` §7 specified, transcribed into real Go with
stub bodies. No implementation exists; every method panics or fails.

**Exported surface:**

```
var ErrNoAllowedAlgorithms error

type Algorithm string
const RS256, ES256 Algorithm

type KeySource interface {
	Key(ctx context.Context, kid string) (crypto.PublicKey, Algorithm, error)
}

type Option func(*config)
func WithClockSkew(d time.Duration) Option
func WithIssuer(iss string) Option

type Claims struct {
	Subject, ClientID string
	Audience, Scope   []string
	IssuedAt, ExpiresAt time.Time
	JTI string
}

type Validator struct{ /* unexported */ }
func New(source KeySource, allowed []Algorithm, opts ...Option) (*Validator, error)
func (v *Validator) ValidateAccessToken(ctx context.Context, raw, wantAudience string) (Claims, error)
func (v *Validator) ValidateIDToken(ctx context.Context, raw, clientID string) (Claims, error)

type JWKSSource struct{ /* unexported */ }
func NewJWKSSource(jwksURL string, httpClient *http.Client, refetchLimit int, refetchWindow time.Duration) *JWKSSource
func (s *JWKSSource) Key(ctx context.Context, kid string) (crypto.PublicKey, Algorithm, error)
```

This matches `docs/ARCHITECTURE.md` §7 exactly — no deviation to record yet.
The next row (M2) is where a real deviation becomes possible, once
`ValidateAccessToken` has a body and a first caller.

---

## M2 — Authorization code + PKCE (issue #31)

**Consumer driving this entry:** none yet, honestly — the stated consumers
(the gateway, the demo resource server) do not exist until M6; `ValidateIDToken`
and `JWKSSource.Key` are still M7/M3 stubs. What drove every signature change
below is this issue's own test suite: `ValidateAccessToken` needed a way to
tell its caller *which* class of thing was wrong (malformed input, wrong
token type, an algorithm outside the allow-list, or a claim that failed —
each exercised by a distinct test with its own negative control), which a
single generic error could not express.

**Exported surface, changed from M0:**

```
// New — four error vars added, one per rejection category
// ValidateAccessToken now checks, each.
var ErrMalformedToken error      // not a single-sig compact JWS; no kid; unresolvable kid
var ErrWrongTokenType error      // protected header's typ doesn't match what the caller needs
var ErrAlgorithmNotAllowed error // kid's registered algorithm isn't in this Validator's allow-list
var ErrClaimsInvalid error       // signature verified, but a claim failed (exp/nbf/iat/iss/aud/required)
```

Everything else — `Algorithm`, `KeySource`, `Option`, `WithClockSkew`,
`WithIssuer`, `Claims`, `Validator`, `New`'s own signature, `ValidateIDToken`,
`JWKSSource`, `NewJWKSSource`, `JWKSSource.Key` — is byte-for-byte unchanged
from M0. `ValidateAccessToken`'s signature is also unchanged; only its body
went from a panic to a real implementation.

**What the implementation does, since the signature alone doesn't say it:**
the verification algorithm comes only from `KeySource.Key`'s own registered
`Algorithm` for the token's `kid`, passed explicitly to `jws`'s verifier
(RS-06) — the token's own protected header `alg` is read nowhere in this
decision. `jws.Verify`'s own documented default (reject whenever the header's
`alg` disagrees with the algorithm actually used) is a second, independent
layer underneath this — confirmed by testing, not assumed: see
`TestValidateAccessToken_AlgNoneRejected`'s own comment in
`pkg/tokenvalidator/tokenvalidator_test.go` for where that surfaced.
