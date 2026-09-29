# ADR-0014: Access-token revocation is enforced at the gateway only; the TTL bounds it elsewhere

## Status
Accepted — 2026-09-29

## Context
v0.3 of the requirements listed an access-token denylist in Redis and said
`/revoke` accepts access tokens. It did not say who consults the denylist.
The resource server re-validates tokens itself from the JWKS (ADR-0007), with
no access to Redis — so a revoked access token keeps working at any resource
server reached directly, until it expires. Described as complete, the
revocation was partial.

## Decision
- The gateway consults the denylist on every proxied request, keyed by `jti`,
  with a TTL equal to the token's remaining lifetime.
- The resource server does not, and is not given access to Redis.
- The access token lifetime is capped (default 5 minutes, bound 15, RF-12)
  because it *is* the revocation bound at the resource server.
- REQUIREMENTS RF-06 states the scope of the guarantee explicitly.

## The alternative that was rejected
**Introspection at the resource server on every request** (RFC 7662). Makes
revocation immediate everywhere, and turns the AS into a dependency of every
API call — the availability coupling that self-contained JWTs exist to avoid.
**Sharing the denylist with resource servers** couples them to usher's Redis
schema and credentials, which is a larger trust surface than the problem.

## Consequences
- Revocation is immediate at the gateway and eventual (≤ TTL) at a resource
  server reached directly. T-08's residual.
- A Redis loss un-revokes denylisted tokens at the gateway for at most their
  remaining TTL.
- Short TTLs mean more refreshes, which means more Postgres writes (ADR-0002).
