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
