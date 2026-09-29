# ADR-0009: `pkg/tokenvalidator`'s public signature changes are recorded at the end of every phase

## Status
Accepted — 2026-09-29

## Context
`moat` declined to extract a `jwtauth` module and recorded a reopening
criterion: the validator's signature must have stabilized under real use,
measured by how often it changed across a consumer's recent iterations, and
informed by a second consumer. The criterion cannot be evaluated today — there
is no validator in use, so there is no measurement.

usher produces one. `pkg/tokenvalidator` has two consumers inside this
repository from phase 6: the gateway and the demo resource server (RI-05).

## Decision
At the end of every phase, the phase's closing PR appends a row to
`docs/tokenvalidator-api-log.md`: the phase, the exported identifiers added,
removed or changed (from `go doc -all` diffed against the previous phase), and
which consumer drove each change.

## The alternative that was rejected
**Reconstruct the history from `git log` when `moat` asks.** Possible in
principle and unreliable in practice: a signature change inside a large commit
is invisible to a log search, and "which consumer drove it" is not in the diff
at all.

## Consequences
- One small documentation task per phase, on the phase's closing checklist.
- The log is evidence for a decision in *another* repository; it is only useful
  if it is honest about churn, including churn that looks bad.

## Reopening criterion
Stop recording once `moat` has evaluated its criterion against this log and
recorded the outcome, either way.
