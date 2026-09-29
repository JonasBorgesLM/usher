# ADR-0012: Refresh rotation is strict — no grace window for a retried or concurrent request

## Status
Accepted — 2026-09-29

## Context
With rotation, each refresh consumes the presented token and returns a new one.
A legitimate client can still present a consumed token: its request succeeded
but the response was lost, and it retries; or two tabs refresh at once. Many
implementations add a grace window — for a few seconds, presenting the
just-consumed token returns the same successor instead of revoking the family.

## Decision
No grace window. Any presentation of a consumed refresh token revokes the
family and raises a high-severity audit event (RS-11). The concurrency test
requires exactly one issuance from simultaneous exchanges.

## The alternative that was rejected
**A short grace window returning the same successor.** Better experience under
flaky networks, and common in production IdPs. Rejected because:

- it creates a window in which a stolen token and the legitimate one can both
  be used without detection — the exact event RS-11 exists to catch;
- returning "the same successor" means storing the successor in a retrievable
  form, which conflicts with RS-10 (only hashes at rest) unless it is kept
  encrypted, adding a key to manage;
- the study value of this project is the detection mechanism, and a window
  blurs the property being studied.

## Consequences
- A legitimate client that retries a refresh whose response was lost is logged
  out. Clients must serialise refreshes, and this is documented for integrators.
- Audit will show reuse events that are not attacks. They are still reported
  at high severity: telling them apart is not something the AS can do safely.

## Reopening criterion
Reopen if, once a client other than a test harness uses usher, false-positive
revocations exceed 1% of refreshes over a week — and only together with a
design for storing the successor that keeps RS-10.
