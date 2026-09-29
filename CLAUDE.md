# CLAUDE.md

Guidance for Claude Code in this repository. The general engineering rules live
in `~/.claude/CLAUDE.md` and are not repeated here.

## Project Overview

usher is an OAuth 2.1 / OpenID Connect authorization server and reverse proxy in
Go, built from scratch to study the parts of authentication that are easy to get
subtly wrong. **A study project, not production software** — see the non-goals
in [`REQUIREMENTS.md`](REQUIREMENTS.md) §1.1 before adding anything that looks
like a feature.

**Status: pre-implementation.** Requirements, threat model and ADRs exist; code
does not. Phase 0 (milestone `M0`) is the next work.

Read these before changing anything structural:

| | |
| --- | --- |
| [`REQUIREMENTS.md`](REQUIREMENTS.md) | Binding. `RF-`, `RS-`, `RNF-`, `RI-` ids, cited everywhere |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | `T-nn` threats, their mitigations and **residuals** |
| [`docs/adr/README.md`](docs/adr/README.md) | Decisions, reopening criteria, and the **open questions** |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Git flow, commit scopes, testing and review rules |

## Architecture

One binary, `cmd/usher`, holds the authorization server and the gateway
(ADR-0001). The boundary that matters: **`internal/oauth` and `internal/oidc`
never import `internal/proxy`, and `internal/proxy` never imports them.** They
meet only in `pkg/tokenvalidator`, `internal/keys` and the stores. CI asserts
this with `go list -deps` — do not "fix" a failing boundary check by moving a
type into a shared package without an ADR.

`cmd/resource-server` is a deliberately small demo upstream that re-validates
tokens itself (ADR-0007, ADR-0013). Keep it small; it is not a second product.

Storage split is REQUIREMENTS §7.1, and it is a security decision, not tuning:
refresh families are in **Postgres** because losing them makes reuse detection
fail silently (ADR-0002). Only state whose loss fails safe goes in Redis.

## Stack

- **Go 1.26.6 floor** — a security floor inherited from `moat/redisstore`, not a
  feature choice (ADR-0008). Do not lower it; do not "simplify" it to `1.26`.
- `net/http` + `chi`, `lestrrat-go/jwx/v4`, `pgx/v5`, `go-redis/v9`,
  `golang.org/x/crypto/argon2`, `testcontainers-go`.
- First-party: `moat` + `moat/redisstore` (edge security), `bastion` (outbound
  breaker). **Pinned exactly, never upgraded by a bot** (ADR-0011, ADR-0016).
- Every direct dependency must be on the allow-list in
  `.github/dependency-allowlist.txt` with the ADR that justifies it (RNF-09).
  Adding a dependency means an ADR first, then the allow-list line.

## Commands

```bash
go build ./... && go vet ./... && go test -race ./...
go test -tags=integration -race ./...     # needs Docker (testcontainers)
golangci-lint run ./...
gosec -tests -exclude-generated ./...
govulncheck ./...
./.github/scripts/check-docs.sh           # ids, threats, ADR index, links
./.github/scripts/check-boundaries.sh     # ADR-0001
./.github/scripts/check-dependencies.sh   # RNF-09
docker compose up                         # once phase 0 adds it
```

Until the first package exists, the Go jobs print a notice and pass; the notice
disappears with the first `.go` file. That is the only intended skip.

## Conventions

- **Git flow:** PRs target `develop`; `main` is releases, and tracks `develop`
  until `v0.1.0`. Branches `feat/`, `fix/`, `docs/`, `ci/`, `test/`.
- **Conventional Commits** with this project's scopes (CONTRIBUTING.md). CI
  checks every commit and the PR title. Cite ids in the body: `Refs RS-04`.
- **Ids are Portuguese-derived** — `RF` functional, `RS` security, `RNF`
  non-functional, `RI` integration — as in `cistern`. Cross-project citations
  are qualified: `bastion/ADR-0009`, `crier/IR3`.
- **ADRs are amended, never rewritten.** CI fails a PR that removes a line from
  an existing ADR.
- Errors to clients follow RFC 6749 §5.2 with fixed codes and no internal
  detail (RS-25). `invalid_grant` is deliberately ambiguous — do not make it
  "more helpful".

## Testing

- Every `RS-` requirement has a test that attempts the attack, and that test
  has been **seen failing** with the protection removed. The control is noted in
  a comment above the test. Without it the requirement counts as unimplemented.
- Where a requirement covers a class of points (every credential route has
  `no-store`, every HTML response forbids framing), the test enumerates the
  points from the router, never from a hand-written list.
- Concurrency properties (RS-04, RS-11) are tested with real goroutines under
  `-race`: simultaneous exchanges yield exactly one issuance.
- Integration tests use real Postgres and Redis. An unavailable container fails
  in CI; it never skips silently.

## Known Constraints

- Access-token revocation is gateway-local; a resource server reached directly
  honours a revoked token until `exp` (ADR-0014). Short TTLs are the mitigation.
- Redis must run `noeviction`, and usher refuses to start when it cannot verify
  it — which excludes managed Redis offerings that block `CONFIG` (ADR-0003).
- Strict refresh rotation logs out a client whose retry races its own request
  (ADR-0012). That is accepted, not a bug to fix with a grace window.
- `task-api` is **not** the resource server in the MVP, and its opaque-session
  decision is not ours to reopen (ADR-0013).

## Important Decisions

All in [`docs/adr/`](docs/adr/README.md). Read an ADR's `## Amendment`
sections as part of it: ADR-0015 and ADR-0017 were Proposed and were accepted by
amendment, which is where their answers live. A question still listed as open
in the index is not decided — resolve it in an ADR before implementing it.

## Non-negotiable Invariants

Each is a defect if violated. The requirement id is where the reasoning is.

1. **Never redirect to an unverified `redirect_uri`.** `/authorize` validates
   `client_id`, then exact-matches `redirect_uri`, and only then may report
   errors by redirect (RS-28, RS-02). Reversing the steps looks identical and is
   an open redirect.
2. **Consumption is atomic.** Codes and refresh tokens are consumed with a single
   compare-and-set; never read-then-write (RS-04, RS-11).
3. **The token never chooses how it is verified.** The algorithm allow-list is
   fixed at construction (RS-06). An ID token is never an API credential (RS-08).
4. **Strip `X-Auth-*` before injecting**, as an allow-list of what passes (RS-17).
5. **Secrets are `secret.Value`.** No `==` or `bytes.Equal` on a secret; nothing
   secret in a log, error, audit event or span (RS-15, RS-23).
6. **Infrastructure failure denies** (RNF-04), and incomplete or out-of-bounds
   configuration refuses to start (RNF-05).
7. **Two rotations at login** — CSRF token *and* session id (RS-12b).
   `csrf.Rotate` does only the first.

## Tooling notes

- There is no frontend beyond server-rendered login and consent pages, which are
  deliberately plain. Impeccable, the animation skills and Figma have nothing to
  do here.
- `graphify-out/` is per machine and ignored. Before code exists the graph is a
  document cross-reference map; it will answer "who calls this" with nothing,
  correctly.
- `warden` and `sapper` (sibling repositories) verify the running stack (RI-06).
  Record the checks that did not apply and why — a clean report that verified
  nothing is worse than none.
