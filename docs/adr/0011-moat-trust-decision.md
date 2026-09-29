# ADR-0011: `moat` is trusted as a first-party dependency, pinned exactly and never auto-upgraded

## Status
Accepted — 2026-09-29

## Context
`moat` supplies the edge security usher relies on: rate limiting, CSRF,
security headers, trusted-proxy resolution and redacted secret types. It is
first-party — same author — pre-1.0, not independently audited, with a bus
factor of one. Its history includes a breaking rename of `ratelimit.Store` in a
minor release and a published satellite tag (`redisstore/v0.2.0`, since
retracted) that did not compile for anyone resolving it fresh.

## Decision
- Use it. Being its first consumer under protocol load is a stated goal
  (REQUIREMENTS §1).
- Pin both modules to exact versions: core `v0.2.0`, `redisstore v0.2.2`.
- Exclude `moat` from Dependabot. An upgrade is a manual PR that builds and
  tests from a clean directory with `GOWORK=off`, so a stale satellite pin
  cannot hide behind a workspace.
- Requirements and ADRs cite the *property* `moat` provides, and note that it
  supplies it today (REQUIREMENTS §7.3). If the library changes or is replaced,
  the requirement outlives it.

## The alternative that was rejected
**Implement the edge controls in-tree.** No external trust question, and every
line reviewable here. Rejected because it duplicates a library that exists to
be exercised by exactly this kind of consumer, and because its failure modes
are already documented there — re-deriving them here would re-learn them.

## Consequences
- A `moat` defect is a usher defect. Findings go upstream as issues, and usher
  records the workaround until a fixed version is pinned.
- Security fixes in `moat` are not picked up automatically. Watching its
  releases is part of maintaining usher.
- Where the boundary sits is documented, not assumed: `moat` does not match
  `redirect_uri`s, rotate session ids, or set server timeouts — those are
  RS-02, RS-12b and RS-21, and they are usher's.
