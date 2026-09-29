# ADR-0002: Postgres, not Redis, is the source of truth for refresh token families

## Status
Accepted — 2026-09-29

## Context
Refresh tokens are short strings looked up on every refresh, with an expiry —
the shape Redis is built for, and the store already present for rate limits and
codes. But reuse detection (RS-11) works by remembering that a token was
*consumed*. If that memory disappears, a consumed token looks like one never
seen, and the replay is not detected — it is simply rejected as unknown at best,
or, if the family record went with it, the stolen token's successor keeps
working.

## Decision
Refresh families and their token records live in Postgres. Consumption is a
single conditional `UPDATE ... WHERE consumed_at IS NULL` whose affected-row
count is the compare-and-set RS-11 requires. Redis holds only state whose loss
fails safe (REQUIREMENTS §7.1).

## The alternative that was rejected
**Redis with persistence (AOF, `appendfsync always`).** It closes most of the
gap and keeps one store on the hot path. It was rejected because the failure it
leaves — a failover to a replica that had not received the last writes, or an
operator enabling eviction under memory pressure — is silent, and silent is
the worst available failure for a detection mechanism: the system keeps
answering, and the answer is "not a replay" when it was one.

## Consequences
- Every refresh is a Postgres write. At the MVP's scale this is irrelevant; it
  is the number to watch if usher ever sees real load.
- Postgres is on the critical path of refresh, so a Postgres outage stops
  refresh (RNF-04 — fail closed). Access tokens already issued keep working
  until expiry.
- Family revocation (RF-06, RF-13) is a transactional update, which is easy to
  make atomic here and hard to make atomic across Redis keys.
