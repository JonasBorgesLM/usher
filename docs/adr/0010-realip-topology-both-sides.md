# ADR-0010: The `realip` trust topology is declared on both sides, and never `0.0.0.0/0`

## Status
Accepted — 2026-09-29
Amended — 2026-09-29, with the concrete range below (#8)

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

## Amendment — the compose network's concrete range (#8)

`docker-compose.yml`'s `usher` network is fixed at `172.28.0.0/24`, rather
than Compose's dynamic default, specifically so this ADR could name a
concrete range instead of one that changes across machines and runs.

Once M2 adds `usher` as a compose service, it is pinned to a static address
within that range — `172.28.0.10` — and the demo resource server's trusted
set (added in M6) is that single address, not the whole `/24`. Trusting one
address is a tighter boundary than trusting the subnet: anything else that
later joins the network does not inherit the gateway's trust by virtue of
being on it.

Outside compose — a real deployment — both ranges are the operator's own
infrastructure's, per the ADR's main decision above; this amendment is the
local-development instance of it, not a general rule.
