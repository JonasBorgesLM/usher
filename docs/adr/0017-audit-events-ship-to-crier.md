# ADR-0017: Audit events are structured log records shipped to `crier`, not rows in Postgres

## Status
Proposed — 2026-09-29
Accepted — 2026-09-29, with the answers in the Amendment below (#2)

## Context
RF-09 requires authentication events recorded "in structured, queryable form".
v0.3 did not say where. `crier` — a log-control service in this ecosystem —
was designed with usher as its audit-event source (`crier/IR3`): it never
samples at or above `ERROR`, redacts fail-closed, overwrites client-asserted
source identity, and counts every drop by reason.

## Decision (proposed)
- `internal/audit` defines a versioned event schema (event type, outcome,
  subject, client, request id, source address — never a secret, RS-23).
- Events are emitted as structured `slog` records and exported to `crier`'s
  ingestion endpoint with usher's own credential.
- Queryability is `crier`'s backend's; usher keeps no audit table.

## The alternative that was rejected
**An append-only `audit_events` table in Postgres.** Durable, transactional with
the event it records (a reuse detection and its audit row commit together), and
queryable with SQL. Rejected in this proposal because it makes usher a log store
as well as an IdP, and because the ecosystem already has a component whose job
is exactly this — with redaction and drop accounting usher would otherwise
reimplement.

## Consequences
- Audit delivery is best-effort. `crier` counts its drops, but a dropped
  high-severity event is still dropped (T-19's residual).
- usher's own tests need a way to observe emitted events without a running
  `crier` — an in-process sink behind the same interface.

## Open questions — why this is Proposed
1. Is best-effort delivery acceptable for RS-11's reuse-detected event, or does
   that one event class also need a durable local record?
2. What does usher do when `crier` is unreachable — buffer (bounded), drop and
   count, or refuse to start (RNF-05)?

Accept, with the answers, before phase 1 emits its first login event.

## Amendment — accepted (#2)

The two open questions, answered.

1. **The reuse-detected event is durable where the revocation is.** Family
   revocation is already a Postgres `UPDATE` (ADR-0002). The same statement
   records `revoked_at` and `revoked_reason` (`reuse_detected`, `revoked_by_client`,
   `admin`, `consent_revoked`), in the same transaction. So the fact that RS-11
   fired survives any loss downstream, without an audit table: the family row
   *is* the record. The event still goes to `crier` for correlation and alerting.
   Every other event class is best-effort.
2. **When `crier` is unreachable: bounded buffer, then drop and count.** Events
   queue in a fixed-size in-memory buffer; when it is full, new events are
   dropped and a counter per drop reason is incremented and logged locally.
   `/readyz` does not depend on `crier`: an audit sink outage does not stop
   logins. Refusing to start was rejected because it couples usher's
   availability to a log pipeline at boot while leaving the same gap after boot;
   failing closed was rejected for the same coupling, permanently.

T-19's residual changes accordingly: losing `crier` loses events, but not the
record that a refresh family was revoked for reuse.
