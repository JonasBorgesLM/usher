# ADR-0007: The gateway forwards the original token, and the resource server re-validates it

## Status
Accepted — 2026-09-29

## Context
After the gateway validates a bearer token, it can either forward it, replace
it with something internal (a signed assertion, a header set), or strip it and
let the resource server trust the connection. The last is the common one, and
it makes the internal network a trust boundary: anything that reaches the
resource server without passing the gateway is whoever it says it is (T-13).

## Decision
- The original `Authorization` header is forwarded unchanged (RF-08).
- The resource server validates signature, `iss`, `aud`, `exp` and `typ`
  against the JWKS itself (RS-18), with `pkg/tokenvalidator`.
- The gateway additionally injects `X-Auth-*` identity headers after stripping
  any inbound ones (RS-17). They are a convenience for consumers that pin the
  gateway as their only peer (RI-04), never the basis of an authorization
  decision in this repository.

## The alternative that was rejected
**Token exchange at the gateway** — the gateway swaps the client's token for a
short-lived internal one scoped to the upstream. It gives the upstream a token
it can trust more narrowly, and hides the client's token from it. Rejected for
the MVP because it adds a second token type, a second issuer path and a second
set of claims to validate, for a benefit that matters when upstreams are less
trusted than the gateway — which is not this deployment.

## Consequences
- Validation happens twice per request. It is a signature check against a
  cached key; the cost is small and is the price of defence in depth.
- The resource server sees the client's token. A compromised upstream can
  replay it at another upstream that accepts the same audience — RS-19's
  per-route audience is what limits that.
- The gateway's denylist (RF-06) is invisible to the resource server
  (ADR-0014).
