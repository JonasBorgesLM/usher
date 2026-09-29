# ADR-0010: The `realip` trust topology is declared on both sides, and never `0.0.0.0/0`

## Status
Accepted — 2026-09-29

## Context
The per-IP rate-limit axis (RS-22) keys on the client address. Behind a proxy,
that address comes from `X-Forwarded-For`, which the client controls unless the
reader knows which hops to believe. `moat`'s `realip` derives the key from the
first *untrusted* peer — correct only when the trusted set is right.

usher sits in the middle of two such relationships: a load balancer may front
it, and it fronts the resource server.

## Decision
- usher declares the CIDRs of whatever fronts it, or declares direct exposure.
  Neither declared is a startup error.
- The demo resource server declares usher's CIDR as its only trusted proxy.
- An empty trust set and `0.0.0.0/0` (or `::/0`) are construction errors on
  both sides. The latter matters most: it is the easy way out for someone who
  does not know the balancer's range, and it makes every forged
  `X-Forwarded-For` authoritative.

## The alternative that was rejected
**Trusting a fixed number of hops** (`X-Forwarded-For`'s *n*-th entry from the
right). Simpler to configure and wrong the moment a hop is added or removed —
silently, with rate limiting keyed on the wrong address.

## Consequences
- Deployment documentation must name both ranges; the compose file sets them
  for its own network.
- A misdeclared range still fails silently in one direction (too narrow: every
  client shares the proxy's bucket). `sapper`'s ramp-up scenario is the check
  that would expose it (RI-06).
