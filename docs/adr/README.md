# Architecture Decision Records

Every structural decision is recorded here, **before the code it governs**. An
ADR is never edited to reflect a later change of mind: it is amended with a
section naming what superseded which part, so the reasoning that was current at
the time stays readable.

CI enforces the mechanical form: an existing ADR may gain lines, never lose
them. A genuine typo is the one exception, and it needs the `adr-typo` label on
the PR — visible, and spelled out by a human.

New records start from [`TEMPLATE.md`](TEMPLATE.md), which is deliberately not
named `0000-` so it does not read as a decision or trip the index check.

## Index

| ADR | Title | Status | Amended by |
| --- | --- | --- | --- |
| [`0001`](0001-one-binary-rigid-package-boundaries.md) | AS and gateway in one binary, with package boundaries CI enforces | Accepted | — |
| [`0002`](0002-postgres-holds-refresh-families.md) | Postgres, not Redis, is the source of truth for refresh families | Accepted | — |
| [`0003`](0003-fail-closed-rate-limiting-noeviction.md) | Rate limiting fails closed; `noeviction` is an infrastructure requirement | Accepted | — |
| [`0004`](0004-jwx-v4-over-golang-jwt.md) | `jwx/v4` for JOSE and JWKS, over `golang-jwt/v5` | Accepted | — |
| [`0005`](0005-argon2id-versioned-bounded.md) | Argon2id, versioned per record, under a concurrency bound | Accepted | — |
| [`0006`](0006-explicit-middleware-composition.md) | Explicit middleware composition, not `preset.API` | Accepted | — |
| [`0007`](0007-forward-original-token-rs-revalidates.md) | Forward the original token; the resource server re-validates | Accepted | — |
| [`0008`](0008-go-floor-1-26-6.md) | Go floor 1.26.6, inherited from `moat/redisstore` | Accepted | — |
| [`0009`](0009-record-tokenvalidator-signature-changes.md) | Record `tokenvalidator` signature changes every phase | Accepted | — |
| [`0010`](0010-realip-topology-both-sides.md) | `realip` topology declared on both sides, never `0.0.0.0/0` | Accepted | — |
| [`0011`](0011-moat-trust-decision.md) | `moat` trusted as first-party, pinned exactly, never auto-upgraded | Accepted | — |
| [`0012`](0012-strict-refresh-rotation-no-grace-window.md) | Strict refresh rotation — no grace window | Accepted | — |
| [`0013`](0013-demo-resource-server-in-repository.md) | Demo resource server in this repository; `task-api` deferred | Accepted | — |
| [`0014`](0014-access-token-revocation-is-gateway-local.md) | Access-token revocation is gateway-local; the TTL bounds it elsewhere | Accepted | — |
| [`0015`](0015-signing-keyset-custody-and-rotation.md) | Signing keys as a mounted keyset with explicit windows | Accepted | [Amendment (#3)](0015-signing-keyset-custody-and-rotation.md#amendment--accepted-3) |
| [`0016`](0016-bastion-guards-the-proxy-path.md) | `bastion` guards the proxy path, under `bastion/ADR-0009` | Accepted | — |
| [`0017`](0017-audit-events-ship-to-crier.md) | Audit events ship to `crier`, not Postgres | Accepted | [Amendment (#2)](0017-audit-events-ship-to-crier.md#amendment--accepted-2) |
| [`0018`](0018-embedded-forward-only-migrations.md) | Migrations are embedded SQL, forward-only, under an advisory lock | Accepted | — |

## Reopening criteria on the record

Decisions carrying an explicit trigger, so "revisit later" is not a synonym for
never.

| ADR | Reopen when |
| --- | --- |
| 0001 | The proxy must scale independently of `/token`, or the keys need a process boundary from proxy code |
| 0004 | `jwx`'s cache cannot express RS-09's rate-limited refetch without more wrapping than a hand-written cache |
| 0006 | `moat`'s preset models session and bearer auth per group, or the hand-composed chains drift more than once |
| 0009 | `moat` has evaluated its `jwtauth` criterion against the log |
| 0012 | False-positive revocations exceed 1% of refreshes for a week, with a successor-storage design that keeps RS-10 |
| 0013 | `task-api` records an ADR accepting usher's JWTs |

## Open questions

Deferred deliberately and listed here, because an undecided question that looks
decided is the one that gets implemented by accident.

| Question | Blocks | Where |
| --- | --- | --- |
| Whether `Clear-Site-Data: "cookies"` on logout may clear the whole registrable domain | Phase 7 | REQUIREMENTS RS-27 |
