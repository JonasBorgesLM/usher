<!--
Title must be a Conventional Commit -- it becomes the subject on a squash merge:
  feat(oauth): consume authorization codes atomically
Target branch: develop.
-->

## What and why

<!-- The diff says what changed. Say why it needed to. -->

## Traceability

- Requirements: <!-- RS-04, RF-02 -- or "none" with a reason -->
- Threats: <!-- T-01 -- or "none" -->
- Decisions: <!-- ADR-0002 -- or "none" -->
- Closes: <!-- #33 -->

## Security checklist

Delete the lines that do not apply; do not delete the ones that do.

- [ ] This touches an `RS-` requirement, and its test has been **seen to fail**
      with the protection removed. The negative control is noted above the test.
- [ ] The residual of every threat this touches is still what
      `docs/THREAT-MODEL.md` says — or the threat model is updated here.
- [ ] No secret reaches a log, error, audit event or span (RS-23).
- [ ] `/authorize` still validates `client_id`, then `redirect_uri`, before any
      redirect (RS-28).
- [ ] Code and refresh consumption are still single compare-and-set operations
      (RS-04, RS-11).
- [ ] No new dependency — or it has an ADR and an allow-list entry (RNF-09).

## Documentation

- [ ] A structural decision here has an ADR, written **before** the code.
- [ ] An existing ADR was amended, never rewritten.
- [ ] No question listed as open in `docs/adr/README.md` was resolved silently.
- [ ] `./.github/scripts/check-docs.sh` passes locally.
- [ ] Phase-closing PR only: `docs/tokenvalidator-api-log.md` has this phase's row (ADR-0009).
