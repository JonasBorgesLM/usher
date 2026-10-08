# Security policy

usher is a study project and **not intended for production** — see the
non-goals in [`REQUIREMENTS.md`](REQUIREMENTS.md) §1.1. Reports are still
welcome and taken seriously: finding where a carefully written authorization
server goes wrong is the point of the project.

## Reporting

Use GitHub's **private vulnerability reporting** on this repository
(*Security → Report a vulnerability*). Do not open a public issue.

Include what you did, what you expected, and what happened. A requirement or
threat id (`RS-04`, `T-07`) is helpful if one applies, and a finding that shows
a requirement is wrong is as valuable as one that shows the code is.

## Scope

In scope: anything in this repository — the authorization server, the gateway,
the demo resource server, `pkg/tokenvalidator`, and the documents, where a
documented guarantee is stronger than what the code delivers.

Out of scope: the items in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) §7,
and residuals the threat model already states. A report that a stated residual
is *larger* than stated is in scope.

Vulnerabilities in `moat`, `bastion` or `crier` belong in those repositories.

## Supported versions

`v0.1.0` and later — the latest tag receives fixes.
