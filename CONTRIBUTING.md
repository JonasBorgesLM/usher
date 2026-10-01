# Contributing to usher

## Status

usher is pre-implementation: requirements, threat model and ADRs are written;
production code is not. Work is tracked on the
[project board](https://github.com/users/JonasBorgesLM/projects/7), grouped into milestones `M0` to `M9`, one per phase of
[`REQUIREMENTS.md`](REQUIREMENTS.md) §11. Every issue cites the requirement and
the ADR it closes, and has a checkable "done when".

---

## Git flow

**`develop` is where work lands. `main` is what has been released.**

- Every pull request targets `develop`. Nothing targets `main` directly.
- At each release, `develop` merges into `main` and the tag is cut there, so
  `main` is always a released state — and it is what a visitor sees.
- **Until the first tag exists, `main` tracks `develop`.** There is no released
  state for it to hold, and a default branch showing an empty project is worse
  than one showing unreleased work. After each merge into `develop`, fast-forward
  `main` until `v0.1.0`.
- **Merge `main` back into `develop` when a release finishes.** Release commits
  edit the very files the release exists to change; without the merge back the
  branches diverge in exactly those files. `crier`'s `main` held only an initial
  commit through six milestones because nobody had written down when it should
  be updated.

### Branches

```
feat/<short-name>        feat/pkce-verification
fix/<short-name>         fix/code-consumption-race
docs/<short-name>        docs/adr-0018
ci/<short-name>          ci/boundary-check
test/<short-name>        test/refresh-reuse-negative-control
```

Branch from `develop`. One branch, one subject. A branch name carries the issue
number when there is one: `feat/42-pkce-verification`.

### Stacked pull requests

When phase *N+1* starts before phase *N*'s PR merges, base the new branch on the
old one so its PR shows its own diff. **Retarget the dependent PR to `develop`
before deleting the base branch.**

```bash
gh pr merge 42 --merge                 # merge the lower PR, keep the branch
gh pr edit 43 --base develop           # retarget the dependent PR FIRST
git push origin --delete feat/m1-identity
```

Deleting the base branch while another PR is based on it **closes** that PR, and
the state is stuck both ways: a closed PR cannot be retargeted, and one whose base
is gone cannot be reopened. Recovery is to restore the branch at the commit the PR
was based on, then reopen, retarget, delete.

**This repository deletes head branches automatically on merge.** That closes
the window between "merge the lower PR" and "retarget the dependent PR" in the
sequence above — GitHub can delete the base branch before the retarget command
runs. The reliable order is to **retarget the dependent PR to `develop` before
merging the lower one at all**: its diff temporarily shows both PRs' commits,
which shrinks back to its own once the lower PR merges, and there is no window
where a deletion can close it. `usher/PR-57` was retargeted this way while
`usher/PR-56` was still open, for exactly this reason.

### `Closes #N` only closes on a merge to the default branch

GitHub's closing keywords fire on a merge to the repository's **default**
branch — `main` here, per the branch model above. A pull request merged into
`develop` does not close the issue it cites, even with the exact keyword and
number, and the issue stays open (and, if another issue names it as a
blocker, stays showing as blocked) until `main` catches up.

Close the issue by hand when its PR merges to `develop`:

```bash
gh issue close 33 -c "Closed by #42, merged to develop; not yet on main."
```

Re-opening on a regression is `gh issue reopen`. Do not wait for the release to
`main` to close issues — that turns every milestone's issues into a batch
closed on tag day, disconnected from when the work actually landed.

### Merging

- **Merge commit** for a branch whose commits are each one subject — the history
  is worth keeping. **Squash** for a branch whose intermediate commits are noise.
  Either way the resulting subject is a Conventional Commit; CI checks the PR
  title because a squash uses it.
- Delete the branch after merge, unless another PR is based on it.
- The required status check is the single `CI OK` job. Branch protection names
  that job and nothing else, so adding a job never silently widens the gap
  between "CI passed" and "everything ran".

---

## Commits

**[Conventional Commits](https://www.conventionalcommits.org)**, enforced by the
`commits` job on every commit in a PR and on the PR title (RNF-08).

```
<type>(<scope>)!: <subject>

<body: why, not what>

Refs RS-04
Closes #33
```

| | |
| --- | --- |
| **Types** | `feat` `fix` `docs` `test` `refactor` `perf` `build` `ci` `chore` `revert` |
| **Scopes** | `oauth` `oidc` `keys` `session` `identity` `rbac` `proxy` `audit` `store` `tokenvalidator` `rs` `config` `requirements` `threats` `adr` `docs` `deps` `ci` `security` `claude` |
| **Subject** | imperative, ≤ 72 characters, no trailing period |
| **Breaking** | `!` before the colon **and** a `BREAKING CHANGE:` footer |

```
feat(oauth): consume authorization codes with a single GETDEL
fix(session): rotate the session id before writing the response
docs(adr): accept the keyset custody decision
test(oauth): prove concurrent code exchange issues exactly once
ci: assert the oauth/proxy package boundary
```

**Explain why in the body.** The diff already says what. Cite the requirement,
threat or ADR — those ids are how someone a year from now finds the reasoning,
and CI checks that every id cited anywhere resolves.

**One subject per commit, staged explicitly.** Do not `git add -A` when the tree
holds work on more than one subject. A commit whose message does not describe
everything in it cannot be reviewed or reverted cleanly.

---

## Documentation is part of the change

Requirements are cited by id from ADRs, godoc, tests and commit messages, so the
documents are load-bearing. Enforced mechanically, by the script CI runs:

```bash
./.github/scripts/check-docs.sh
```

1. The ADR index and the ADR files agree, both directions.
2. Every cited `RF-`/`RS-`/`RNF-`/`RI-` id exists in `REQUIREMENTS.md`.
3. Every cited `T-nn` exists in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
4. Every relative link between documents resolves.

Cross-project citations are qualified — `bastion/ADR-0009`, `crier/IR3` — so they
are not checked against this project's numbering.

### ADRs are never rewritten

A change of mind is a new ADR that supersedes the old one, or an `## Amendment`
section appended to it. CI enforces the mechanical form: an existing ADR may gain
lines, never lose them. A genuine typo is the one exception — label the PR
`adr-typo`.

Write the ADR **before** the code. A question listed as open in
[`docs/adr/README.md`](docs/adr/README.md) must not be resolved silently by an
implementation.

---

## Before you write code

1. Find the requirement id your change implements. If there is none, the change
   needs a requirement first.
2. If the change is structural, write the ADR first.
3. If it touches an `RS-`, plan the negative control before the test.
4. If it touches a threat, check the residual in the threat model still holds —
   or update it in the same PR.

---

## Commands

Single module. Go 1.26.6 or newer (ADR-0008). `GOEXPERIMENT=jsonv2` must be
set (ADR-0004's amendment) — `jwx/v4/jwk` does not compile without it.

```bash
export GOEXPERIMENT=jsonv2
go build ./...
go vet ./...
go test -race ./...
go test -tags=integration -race ./...     # real Postgres and Redis, via testcontainers
golangci-lint run ./...
gosec -tests -exclude-generated ./...
govulncheck ./...
./.github/scripts/check-docs.sh
./.github/scripts/check-boundaries.sh     # ADR-0001
./.github/scripts/check-dependencies.sh   # RNF-09
```

---

## Testing rules

- Table-driven, `t.Run` subtests, asserting the specific behaviour.
- Integration tests use testcontainers against real Postgres and Redis. Never an
  in-memory fake in their place: a fake that implements `GETDEL` correctly proves
  nothing about the server that has to. In CI, an unavailable container fails.
- **Every `RS-` test carries a negative control.** Remove the protection, watch
  the test fail, restore it, and note the control above the test:

  ```go
  // RS-04: two concurrent exchanges of one code yield exactly one issuance.
  // Negative control: verified failing against a store that GETs then DELs.
  ```

  If you cannot make a check fail on demand, say so in the PR rather than
  claiming coverage.
- **A negative assertion is satisfied by a tool that never ran.** Assert the
  expected answer, not the absence of a wrong one.
- **Order is often the requirement** (RS-28, the middleware chain in ADR-0006).
  Test the order, usually with a fake that proves the second step never ran.

---

## Reviewing

In this order:

1. Which requirement does this implement, and does the code match its wording?
2. Which threat does it touch, and is its residual still what the threat model
   says?
3. Has the `RS-` test been **seen to fail**?
4. Does it violate an invariant in [`CLAUDE.md`](CLAUDE.md)?
5. Does it add a dependency? Then it needs an ADR and an allow-list entry
   (RNF-09).

### Reviewing a Dependabot pull request

A dependency bump is a supply-chain change with the blast radius of a
hand-written commit. Read the changelog between the two versions, not just the
numbers. Dependabot is configured **not** to touch `moat` or `bastion`
(ADR-0011, ADR-0016); a PR bumping either means the ignore rule was removed, and
that is the review.

---

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md). Do not open a public issue.
