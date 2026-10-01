# ADR-0004: `lestrrat-go/jwx/v4` for JOSE and JWKS, over `golang-jwt/jwt/v5`

## Status
Accepted — 2026-09-29

## Context
usher signs JWTs, publishes a JWKS, and — in `pkg/tokenvalidator` — fetches,
caches and refreshes a remote JWKS with rate-limited refetch on unknown `kid`
(RS-09). It must verify against an algorithm allow-list fixed at construction
(RS-06).

## Decision
`github.com/lestrrat-go/jwx/v4` (v4.5.0 at the time of writing), pinned exactly.
Its JWK/JWKS model — key sets, `kid` lookup, key parsing from JWKS documents,
and a cache with refresh — is the part of this project that would otherwise be
hand-written, and hand-written JWKS parsing is where key-confusion bugs live.

The validator is still configured so the token's `alg` header never chooses the
verification method: keys are registered with their algorithm, and the accepted
set is built from configuration (RS-06).

## The alternative that was rejected
**`golang-jwt/jwt/v5`.** Smaller, more widely used, and its `WithValidMethods`
makes the allow-list explicit. It has no real JWK/JWKS support, so usher would
write JWKS parsing, `kid` resolution and cache refresh itself — the code this
project should *study*, arguably, but not the code it should get wrong on the
way to studying the protocol. If the JWKS cache turns out to be the interesting
part, that is a reason to revisit, not to start there.

## Consequences
- A larger dependency with a larger API surface; its own `alg` handling must be
  pinned by tests (RS-06's negative controls), not assumed.
- A major-version dependency in the security path: upgrades are manual and
  reviewed like `moat`'s (ADR-0011), not merged from a bot.

## Reopening criterion
Reopen if `jwx`'s cache cannot express RS-09's rate-limited refetch without
wrapping it in more code than a hand-written cache would be.

## Amendment — GOEXPERIMENT=jsonv2 is required (#24)

Discovered implementing `internal/keys` (issue #24, not anticipated when this
ADR was written): `jwx/v4`'s `jwk` package imports `encoding/json/v2` and
`encoding/json/jsontext`, both gated behind Go's `jsonv2` experiment. Without
`GOEXPERIMENT=jsonv2` set, any build that imports `jwx/v4/jwk` — and therefore
`internal/keys`, and transitively almost everything built on it — fails to
compile, not merely to lint.

**Accepted, not reopened.** The alternative considered was reverting to an
earlier `jwx` major version or to `golang-jwt/v5` (this ADR's own rejected
alternative), both of which would mean writing JWKS parsing and `kid`
resolution by hand — exactly the cost this ADR already weighed against
`golang-jwt/v5` and rejected. `GOEXPERIMENT=jsonv2` is set workflow-wide in
`.github/workflows/ci.yml` and documented in `CLAUDE.md`'s Stack section.

**What this costs, stated rather than hidden:** `jsonv2` is an experimental
Go feature with no compatibility guarantee across Go releases, in a
dependency that sits in the signing path. If a future Go release changes or
removes it, this project's floor (ADR-0008) pins an exact toolchain anyway,
so the risk is bounded to upgrade time, not runtime — the same shape as
`moat`'s pre-1.0 trust decision (ADR-0011).

**Reopening criterion, in addition to the one above:** reopen if a stable
(non-experimental) Go release changes `jsonv2`'s behavior in a way that
breaks `internal/keys`, or if `jwx` drops the experimental dependency in a
later `v4` patch — either would remove the reason for this amendment.
