# ADR-0006: Middleware chains are composed explicitly per route group, not through `preset.API`

## Status
Accepted — 2026-09-29

## Context
`moat` ships `preset.API`, which assembles headers, rate limiting, body limits
and CSRF into one chain, requires the proxy topology to be declared, and makes
`DisableCSRF: true` explicit and greppable. It is a defensible option, and
earlier criticism of it — a silently shared rate-limit bucket — was fixed in
`moat` v0.2.0.

usher has five route groups with different needs (REQUIREMENTS §7.2): CSRF on
the browser forms only, client authentication on `/token`, bearer auth and RBAC
on `/api/**`, weighted limits on the credential routes.

## Decision
Compose each chain explicitly from `moat`'s packages, in the fixed order
`secureheaders → ratelimit → validate.MaxBodyBytes → [csrf] → [auth] → [rbac] →
handler`. The order is the requirement: headers outermost so rejections carry
them, the body limit before CSRF because CSRF parses the body.

## The alternative that was rejected
**Two `preset.API` chains** — one with CSRF for the browser routes, one without
for the protocol routes. It covers the first two groups well and gives up on
`/authorize` (session auth, no CSRF, moderate limit) and `/api/**` (bearer +
RBAC), which the preset does not model. Mixing presets for some groups and
hand-composition for others means two ways of building a chain in one binary,
and the audit question "what runs on this route?" would have two answers to
look up.

## Consequences
- More wiring code, and the order must be tested as a property: every route's
  chain is enumerated from the router and checked (REQUIREMENTS §10), so a new
  route cannot silently skip a layer.
- usher does not benefit automatically from future preset improvements.

## Reopening criterion
Reopen if `moat`'s preset gains per-group composition that models session and
bearer authentication, or if the hand-composed chains diverge from each other
in a way the property test catches more than once.
