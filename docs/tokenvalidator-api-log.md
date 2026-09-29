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
