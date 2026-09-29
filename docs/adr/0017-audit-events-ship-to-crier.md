# ADR-0017: Audit events are structured log records shipped to `crier`, not rows in Postgres

## Status
Proposed — 2026-09-29

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
