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

## Amendment — which upstream answers count as failure (#118)

The rejected-alternative paragraph above left "what counts as a failure" to
`bastion`. In practice `bastion` could not decide it for this caller:
`WithIsFailure` classifies only the error an operation returns, and a reverse
proxy's `RoundTrip` returns an error only for transport failures. An upstream
that was up but answering `503` to every request counted as a success on every
call, so the circuit never opened against the most common way a dependency
degrades. sapper's fault-injection run (#117) only exercised dropped
connections, which is why it passed.

**Decision:** `502`, `503` and `504` from the upstream count as failures. A
`500` does not — it is usually one request's own bug, and opening the circuit
for it would refuse every request because one endpoint is broken. 4xx never
counts: it describes the request, not the dependency.

**How:** `breakerRoundTripper` returns an unhealthy answer from inside
`bastion.Execute` as an error carrying the response, then unwraps it back into
the response once `Execute` returns. While the circuit is closed the client
still receives the upstream's own `502`/`503`/`504`, body included; only once
the threshold is crossed does the gateway answer with its own `503` and
`Retry-After` (rule 1 above, unchanged).

**The option not taken:** converting an unhealthy answer into the gateway's
own `502` would have been one line shorter, but it would hide the upstream's
own status and body from the client even while the dependency is still being
called — a different response for the same upstream answer, depending only on
whether a breaker is configured.

Whether `bastion` should offer a result-aware classifier instead of this
pattern is `bastion#85`; if it does, this mechanism changes, the decision
above does not.
