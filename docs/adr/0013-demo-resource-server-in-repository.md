# ADR-0013: The MVP's resource server is a demo service in this repository; `task-api` is deferred

## Status
Accepted — 2026-09-29

## Context
RS-18 requires the resource server to validate the JWT itself. `bastion`'s
ADR-0009 names `task-api` as the upstream behind the gateway. But `task-api`
authenticates with opaque, server-side session tokens by a decision recorded in
its own repository, which forbids switching to JWT or adding a second mechanism
without discussion first. Nothing had reconciled the two.

## Decision
- The MVP's resource server is `cmd/resource-server` in this repository. It
  exposes a small protected API, validates tokens with `pkg/tokenvalidator`,
  and is what `docker compose up` brings up behind the gateway (RNF-06, RI-05).
- `task-api`'s authentication decision is not reopened by this project.
  `task-api` behind usher is an extension (REQUIREMENTS §11), gated by an ADR in
  `task-api` first.
- `bastion`'s host-side rules still apply to the proxy path regardless of which
  upstream is behind it (ADR-0016).

## The alternative that was rejected
**Make `task-api` the resource server now.** It is the more realistic target and
the one `bastion` expected. It would make usher's MVP depend on a design change
in another repository, taken under the pressure of this one's schedule — which
is how a decision someone deliberately recorded gets reversed without the
discussion it asked for.

## Consequences
- `pkg/tokenvalidator` gets its second consumer inside this repository, which is
  what ADR-0009's measurement needs.
- The demo service is written only to be protected; it must stay small, or it
  becomes a second product.
- The integration `bastion` issue #32 describes lands against the demo upstream;
  the issue should say so when it is closed.

## Reopening criterion
When `task-api` records an ADR accepting JWTs from usher as a second transport
or mechanism.
