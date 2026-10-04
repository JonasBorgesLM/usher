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

---

## M3 — Key rotation and JWKS (issue #34)

**Consumer driving this entry:** none yet, same honest answer as M2's row —
`JWKSSource` is this package's own extractability candidate for a consumer
that does not exist until M6. What drove the two new error vars is, again,
this issue's own test suite needing to tell a rate-limit refusal (no fetch
even attempted) apart from a confirmed-absent kid (fetched, still not
found) — the two have different operational meanings for whoever logs them,
even though both are failures a resource server treats identically (401).

**Exported surface, changed from M2:**

```
// New — two error vars, one per JWKSSource.Key failure category.
var ErrUnknownKID error        // no key in the most recently fetched JWKS matches this kid
var ErrRefetchRateLimited error // this source's rate-limited refetch budget is exhausted
```

`JWKSSource` and `NewJWKSSource`'s own signatures are unchanged from M0;
`JWKSSource.Key`'s signature is also unchanged — only its body went from a
panic to a real implementation, the same shape `ValidateAccessToken`'s own
M2 entry took.

**What the implementation does, since the signature alone doesn't say it:**
a cache hit never reaches the network. A miss spends one attempt against a
`moat/ratelimit` token bucket (`refetchLimit` per `refetchWindow`, keyed by
a single constant — keying by `kid` would hand an attacker a fresh bucket
per forged value, defeating the limit RS-09/T-15 exist for) before
attempting a fetch; refused attempts return `ErrRefetchRateLimited` without
ever calling out. There is deliberately no separate, time-based cache
refresh in this phase: the cache is replaced only by a fetch a miss
triggered, which is what lets a newly published key be picked up without a
restart — and also means an already-cached kid is served from it
indefinitely until some unrelated miss happens to trigger a refetch that
drops it. That gap is RS-09's own already-documented residual, not a new
one.

---

## M4 — Refresh rotation and revocation (issue #38)

**Added retroactively, as part of #43's own work.** This row should have
been appended when #38 closed; it was not, and the gap sat between the M3
row above and M6's below until this entry filled it. Added now, honestly
dated to the phase that actually produced the change rather than to #43,
since backdating a measurement to the PR that happens to notice a gap
would misreport which phase's own iteration actually drove it.

**Consumer driving this entry:** `cmd/usher`'s own `/revoke` handler
(#38) — the first real, in-process caller this package had, after M0-M3
each built toward one without yet having it.

**Exported surface, changed from M3:**

```
// New — ValidateForRevocation, alongside ValidateAccessToken: the same
// signature verification and claim set (RS-06, RS-07, RS-08's typ
// check), without the audience check a resource-server caller needs
// but /revoke's own caller (the client the token was issued to, not a
// resource server enforcing RS-19) does not have one to check against.
func (v *Validator) ValidateForRevocation(ctx context.Context, raw string) (Claims, error)

// New — WithClock, an Option: overrides what "now" means for
// exp/nbf/iat validation. internal/keys.Load's own WithClock (#32)
// found the same gap first: a caller that issues and validates within
// the same process over an injected, non-real clock needs validation
// to agree with issuance, which jwx's own default (the real system
// clock) cannot.
func WithClock(now func() time.Time) Option
```

Everything else — `Algorithm`, `KeySource`, `WithClockSkew`, `WithIssuer`,
`Claims`, `Validator`, `New`'s own signature, `ValidateAccessToken`'s own
signature, `ValidateIDToken`, `JWKSSource` and its own methods — is
byte-for-byte unchanged from M3.

**What the implementation does, since the signature alone doesn't say
it:** `ValidateAccessToken` and `ValidateForRevocation` share one private
`verify` core; the audience check (`jwt.WithAudience`) is applied only
when the caller's own `wantAudience` is non-empty, which is the one claim
whose requirement differs between the two public methods. `WithClock`
threads a `jwt.ClockFunc` into that same core's `jwt.Parse` call only when
set; a nil clock (the default) leaves jwx's own real-time behavior
unchanged.

---

## M6 — Gateway (issue #43)

**Consumer driving this entry:** `cmd/resource-server` — the second real
consumer this package's own doc comment named from M0 without yet having
one, and the measurement `moat`'s own reopening criterion asked for
(ADR-0009): does the signature stabilize under a second, independent
caller, or does a second consumer need something the first one's own
iteration never surfaced.

**Exported surface, changed from M4:** none. `cmd/resource-server`
constructs a `Validator` with `NewJWKSSource` and calls
`ValidateAccessToken` exactly as `docs/ARCHITECTURE.md` §7 described
before either had a body, and exactly as `internal/proxy`'s own gateway
handler (#40) already does in-process via `Keyset.AsKeySource` instead of
`NewJWKSSource`. Two consumers, reaching the package two different ways
(in-process vs. over HTTP), needed no option, no new error variant and no
signature change between them. That is the measurement itself, not an
absence of one.
