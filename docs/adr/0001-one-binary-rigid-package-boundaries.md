# ADR-0001: The authorization server and the gateway run in one binary, with package boundaries CI enforces

## Status
Accepted — 2026-09-29

## Context
usher has two roles with different blast radii: the authorization server issues
credentials, and the gateway consumes them to forward traffic. Running them as
two services buys independent scaling and deployment, and costs a network hop,
a second deployment unit, and an internal API between them — before there is a
single user to scale for.

The real risk of one binary is not deployment. It is that the two roles grow
into each other until splitting them is a rewrite: the proxy reaching into
token issuance "just to check one thing", the protocol package importing the
proxy's header types.

## Decision
One binary, `cmd/usher`, for the MVP. Inside it:

- `internal/oauth` and `internal/oidc` do not import `internal/proxy`, and
  `internal/proxy` does not import either of them.
- Both may depend on `pkg/tokenvalidator`, `internal/keys` and the stores; that
  shared layer is where they meet.
- The boundary is asserted in CI with `go list -deps`, per package — not left
  to review (RNF-08).

## The alternative that was rejected
**Two binaries from the start.** It makes the boundary physical, which is its
real appeal: nobody can import across a process. But it front-loads a service
contract between AS and gateway that would be designed before either side
exists, and every phase would pay the cost of two deployables and a
compose file that must bring both up for any test. A reachability check in CI
gives most of the same guarantee for a fraction of the cost, and splitting later
stays a deployment change if the check has held.

## Consequences
- One process holds the signing keys *and* terminates proxied traffic. A
  remote-code-execution bug in the proxy path reaches the keys. That is the
  largest cost of this decision, and it is accepted for a study project; T-18's
  residual depends on it.
- A proxy overload and a login outage are the same outage.
- The boundary is only as good as the CI check; the check must be seen failing
  against a deliberate violation before it is trusted.

## Reopening criterion
Split when either (a) the proxy path needs to scale independently of `/token`
under a measured load, or (b) the keys need a process boundary from
internet-facing proxy code — for example, when usher is used anywhere its
non-goals (REQUIREMENTS §1.1) stop holding.
