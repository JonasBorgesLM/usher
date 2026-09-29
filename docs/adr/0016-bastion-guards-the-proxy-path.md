# ADR-0016: `bastion` guards every outbound proxy call, under the host-side rules of `bastion/ADR-0009`

## Status
Accepted — 2026-09-29

## Context
The gateway reverse-proxies to upstreams. Without a breaker, an unhealthy
upstream holds gateway goroutines until the upstream timeout (RS-21) and takes
the gateway down with it (T-17). `bastion` — a first-party resilience library in
this ecosystem — recorded, before this code existed, that the gateway is where
it plugs in first, and fixed two rules the gateway is bound by
(`bastion/ADR-0009`). The work is tracked as `bastion` issue #32, in this
repository.

## Decision
- One named `*bastion.Breaker` per upstream, wrapping the outbound call.
- `bastion.ErrOpenState` and `bastion.ErrTooManyRequests` map to `503` with
  `Retry-After`, never `500` (rule 1).
- The rate limiter runs once, on the way in. A call `bastion` refuses does not
  re-charge the client's `moat` budget (rule 2).
- `bastion` and `moat` meet only in usher's code; neither imports the other.
- Pinned exactly and upgraded manually, as `moat` is (ADR-0011): same author,
  same pre-1.0 status, same reasoning.

## The alternative that was rejected
**A hand-rolled breaker in `internal/proxy`.** Small, and fully under this
project's control. Rejected because the state machine is the easy part; the
decisions around it — what counts as a failure, what a caller-side cancellation
means — are what `bastion` exists to get right, and re-deciding them here would
likely decide them differently from the library written for this gateway.

## Consequences
- A third first-party dependency with a bus factor of one.
- usher becomes `bastion`'s first real integration and should report back what
  its API cost to use.
- `sapper`'s fault-injection scenario (RI-06) is the test that the breaker opens,
  sheds and recovers under load; until it exists, the in-repo probe covers it.
