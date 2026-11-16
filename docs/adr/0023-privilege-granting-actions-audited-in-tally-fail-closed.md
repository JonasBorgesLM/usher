# ADR-0023: Privilege-granting actions are recorded in `tally` before they take effect, and fail closed

## Status
Proposed — 2026-11-16 (#161). Accepted, it supersedes the part of ADR-0017 that
rejected failing closed, for the actions this ADR names as granting privilege.
Accepted — 2026-11-16, with the answers in the Amendment below (#161)

## Context
ADR-0017 ships RF-09's events to `crier`, through a bounded buffer that drops
and counts, and rejected failing closed because it "couples usher's
availability to a log pipeline". For `crier` that is still right: a dashboard
and alerting pipeline must never stop a login. What ADR-0017 does not give is
**evidence**. A `crier` backend is a store its operator can edit, and T-19's
residual is that every event except the reuse fact on the family row can be
lost. Nobody can later show that the token issuances on record are all of
them, or that none was removed.

`tally` is the ecosystem's tamper-evident log: a hash chain, signed
checkpoints published off the host, offline verification. Its `Append`
returns only once an entry is durable, and returns the real error otherwise;
it deliberately has no fail-open or fail-closed mode, because which one is
right depends on the action, and that is the application's domain
(`tally/ADR-0010`). It asks usher for an integration through a port usher
owns (`tally/RI-02`), with a policy by direction of privilege.

Nothing in usher's audit path can carry that today:

- `audit.Emitter.Emit(ctx, e)` returns no error and must not block. A caller
  cannot refuse an action whose record failed, because it never learns that
  it failed.
- `Event.Subject` is the canonical login identifier in clear (RS-35).
  `tally` stores what it is given forever and refuses a person except as a
  random `SubjectRef` from a vault, with the details sealed under a key that
  a deletion request destroys (`tally/RS-14`).
- Of RF-09's event types, only three are emitted: `login_attempt`,
  `revocation` and `refresh_reuse_detected`. `token_issued` and
  `consent_granted`, the grants, are declared and never emitted.

## Decision (proposed)

**1. A second port, beside `Emitter`.** `internal/audit` gains a synchronous,
error-returning port. `Emitter` stays as it is, the `crier` path.

```go
// Recorder records e durably before returning. A nil error means the
// record is stored; any other error means it may not be, and e.ID is
// what a retry reuses.
type Recorder interface {
	Record(ctx context.Context, e Record) error
}
```

`Record` carries an `ID` generated **before** the action and reused on every
retry, so a retry after an unknown outcome is recorded once
(`tally/ADR-0010`). The `tally` adapter implementing it lives in usher
(JonasBorgesLM/tally#52), and `tally` imports nothing of usher's.

**2. Policy by direction of privilege.** What a failed `Record` does depends
on what the action does to privilege:

| Action in usher | Direction | If `Record` fails |
| --- | --- | --- |
| Token issuance: `authorization_code`, `refresh_token`, `client_credentials` | grants | **deny**: `server_error`, no token |
| Consent granted | grants | **deny**: no consent stored, no code issued |
| Login success, which establishes a session | grants | **deny**: no session |
| `/revoke`, a family revoked for reuse, logout | reduces | **execute**, alarm, retry with the same `ID` |
| Login failure, rate-limit rejection, token rejected at the gateway | informational | execute, alarm |

A grant is recorded **before** it takes effect: the token is not returned,
the consent row not committed, the session cookie not set, until `Record`
returns nil. A record without its action is possible (the process dies
between them) and harmless; an action without its record is what an
attacker covering tracks wants, and this ordering rules it out.

A reduction is never blocked by audit: blocking a revocation because the log
is down would leave a compromised token valid (`tally/ADR-0010`'s context).
It executes first, and its record is retried in the background, bounded,
with the same `ID`.

**3. No person in clear.** The subject is a `SubjectRef` from a vault keyed by
RS-35's canonical identifier; anything identifying (source address, user
agent) goes in a payload sealed under that subject's key. The `crier` event
keeps its fields; mirroring to `crier` an event already recorded is allowed,
with no payload (`tally/RI-03`).

**4. A poisoned log is a readiness failure.** After a write or fsync error,
`tally` refuses every later `Append` until it is reopened. Since every grant
then fails closed, `/readyz` reports the log's state, so an orchestrator routes
logins away from the replica instead of failing them there. This narrows
ADR-0017's "`/readyz` does not depend on `crier`": it still does not; it
depends on the local log.

**5. Deployment.** Each replica has its own log and its own `origin`, with a
signing key that is never usher's token keyset (ADR-0015; `tally/RS-06`), and
publishes checkpoints to an anchor the host cannot rewrite. The procedures
(monitoring off the host, a full disk, a poisoned log) are `tally`'s RUNBOOK.

**On acceptance, the requirements become:**

> **RF-09 — Audit.** Authentication events — login success and failure,
> consent, token issuance, refresh reuse detected, revocation, rate-limit
> rejection, token rejected at the gateway — are recorded as structured
> events with a versioned schema. Actions that grant privilege are recorded
> durably before they take effect and are denied when the record fails;
> actions that reduce privilege execute and their record is retried
> (ADR-0023). Where events go is RI-03.
>
> **RI-03 — Audit events go to `tally`, and are mirrored to `crier`.** Every
> RF-09 event is recorded in `tally` through `audit.Recorder` (ADR-0023), with
> the subject as a `SubjectRef` and identifying details sealed. Events are
> also emitted to `crier`'s ingestion endpoint for dashboards and alerting,
> best-effort: when `crier` is unreachable they are buffered, then dropped and
> counted, and `/readyz` does not depend on `crier` (ADR-0017).

## The alternatives that were rejected

**Make `Emitter` return an error and block.** One port instead of two. Rejected
because `Emitter`'s non-blocking contract is right for `crier`, and every
caller of a blocking `Emitter` would inherit a log pipeline's latency for
events that need no durability. Two ports with two contracts are two things,
not one thing with a flag.

**Fail closed on every event.** Uniform and easy to state. Rejected because it
blocks revocation and logout when the log is down: the user who asks to end a
compromised session is told no. That is the failure `tally/ADR-0010` was
written against.

**Keep everything best-effort, as now.** No latency added and no new failure
mode. Rejected for the grants: a best-effort record of a token issuance is
exactly the record that can be missing without anyone being able to tell, and
the point of a tamper-evident log is that its absences mean something.

**A local spool for reductions, now.** It would close the gap in which a
revocation executed while the log was down is lost with the process. Deferred:
it is a second durable store with its own recovery, for a window that exists
only while the log is already failing. The reopening criterion names the
trigger.

## Consequences
- **Issuance now depends on the local disk.** A full disk or an fsync error
  stops logins and token issuance on that replica, on purpose. `tally`'s
  free-space threshold warns before it happens; `/readyz` takes the replica
  out when it does.
- **`/token` gets slower** by one durable append. The budget is not set here;
  see the open question.
- **A new first-party dependency**, `github.com/JonasBorgesLM/tally`: on the
  allow-list (RNF-09) with this ADR, pinned exactly like `moat` (ADR-0011).
  It is stdlib-only, so it brings nothing else.
- **A reduction executed while the log is failing can go unrecorded** if the
  process dies before the retry succeeds. The action itself is not lost (the
  family row and the revocation hold), only its record.
- **Operators gain work**: a signing key per replica, an anchor off the host,
  and verification, as `tally`'s RUNBOOK describes.
- T-19's residual shrinks to the reductions above and to events `tally` never
  received; `crier`'s drops no longer lose evidence.

## Open questions — why this is Proposed
1. **The latency budget on `/token`.** `tally`'s measurements put an
   `Append`'s p99 between 4 and 11 ms with a 2 ms batching delay, on a laptop
   and in a Linux VM on it (`tally`'s `docs/BENCHMARKS.md`); on a production
   disk it is unmeasured. The budget is set from `sapper`'s measurement of
   `/token` through usher with the adapter in place
   (JonasBorgesLM/tally#54), and recorded here as an amendment.
2. **Is login success a grant?** This ADR says yes: it creates a session that
   later grants tokens without a password. The cost is that a log failure
   stops every login, not only token issuance.

## Reopening criterion
A spool for privilege-reducing records (Decision 2) is added when an audit
finding or a real incident shows a reduction executed and never recorded, or
when a deployment runs where the log's failure rate makes that window
routine.

## Amendment — accepted (#161)

Accepted as proposed, with the two open questions answered. It now supersedes
the part of ADR-0017 that rejected failing closed, for the actions Decision 2
names as granting privilege; ADR-0017 still governs the `crier` path.

1. **Login success is a grant.** It fails closed, as Decision 2's table says:
   the session it creates later grants tokens without a password, so a login
   with no record is the same gap as a token issued with no record. The cost
   is accepted: a log failure stops every login on that replica, and
   Decision 4 takes the replica out of rotation.
2. **The latency budget is provisional.** `Record` may add at most **10 ms**
   to `/token`'s p99 on Linux. It is set from `tally`'s measurements (p99 4–7 ms
   in a Linux VM with a 2 ms batching delay), not from a production disk, and it
   is confirmed or replaced by `sapper`'s measurement of `/token` with the
   adapter in place (JonasBorgesLM/tally#54), recorded as a further amendment.
   Until then, a breach of it is a finding to measure, not a reason to fail
   open.

**The dependency is pinned before `tally` has a release.** `tally` has no tag
yet, so the adapter's pull request pins an exact pseudo-version of its
`develop` branch, on the allow-list with this ADR (RNF-09), and moves to
`v0.1.0` when that is tagged. Exactly pinned and never bumped by a bot, as
ADR-0011 does for `moat`.

**The requirements are amended** with the text under Decision 5, in the same
pull request as this acceptance. T-19's residual changes when the adapter
lands, not before: until then nothing records in `tally`.

The work that follows, each in its own pull request: the `audit.Recorder` port
and the `tally` adapter, with the policy of Decision 2 and its failure paths
tested (JonasBorgesLM/tally#52); then `sapper`'s measurement
(JonasBorgesLM/tally#54).
