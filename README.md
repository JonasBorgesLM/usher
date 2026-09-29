# gateway

An OAuth 2.1 / OpenID Connect authorization server and reverse proxy, written
from scratch in Go to study the parts of authentication that are easy to get
subtly wrong.

> **Status: pre-implementation.** The requirements and threat model are written;
> the code is not. Phase progress is in [Roadmap](#roadmap). This is a study
> project and is **not intended for production** — use Keycloak, Hydra or a
> hosted IdP for that.

---

## Why this exists

Most tutorials stop at "issue a JWT, check the signature". The interesting part
starts after that: what happens when a key rotates while tokens signed by the old
one are still in flight, when a stolen refresh token is replayed alongside the
legitimate one, when a login endpoint answers faster for accounts that do not
exist, when a client sends the identity header the gateway was about to inject.

This project implements the flow properly and **writes down the reasoning**, so
it can be inspected rather than trusted. The full requirements and threat model
are in [`REQUIREMENTS.md`](REQUIREMENTS.md); the decision record is in
[`doc/adr/`](doc/adr).

## What it does

- **Authorization Code Flow with PKCE**, plus refresh token rotation with reuse
  detection. `implicit` and `password` are deliberately absent — OAuth 2.1
  removes both.
- **OIDC**: `id_token`, `/userinfo`, discovery, logout.
- **RBAC**, evaluated as the intersection of client scope and user role.
- **Reverse proxy** in front of resource servers, with identity propagation the
  client cannot forge.
- **Key rotation** through a published JWKS, with a retirement window sized so no
  in-flight token is orphaned.

## Security properties

Each of these is a numbered requirement with a test that attempts the attack —
and every test is validated by removing the protection and confirming the test
fails. A test that passes against both implementations is worse than no test,
because it manufactures confidence.

| Property | What it prevents |
|---|---|
| Exact `redirect_uri` match | Open redirect via prefix or wildcard matching |
| Single-use code, replay revokes issued tokens | Authorization code interception |
| PKCE required for confidential clients too | Code theft through logs, history, or a misconfigured redirect |
| Algorithm allow-list fixed at construction | `alg: none` and RS256/HS256 key confusion |
| ID token never accepted as an API credential | The most common OIDC implementation error |
| Rate-limited JWKS refetch on unknown `kid` | The resource server becoming a DoS amplifier |
| Refresh tokens stored as SHA-256 | A database dump yielding usable credentials |
| Atomic compare-and-set on refresh consumption | Concurrent replay slipping through a read-then-write |
| Constant work on login, including the rate-limit axis | User enumeration by timing, message, or throttling behaviour |
| Constant-time comparison for every secret | Byte-at-a-time secret recovery through response timing |
| Inbound `X-Auth-*` stripped before injection | A client claiming any identity it likes |
| Resource server re-validates independently | Treating the internal network as a trust boundary |
| `no-store` on every credential response | Tokens retained by a shared cache or proxy |

## Architecture

The authorization server and the gateway run in one binary with rigid package
boundaries — the protocol package does not import the proxy package, or the
reverse. Splitting them later is a deployment change, not a rewrite.

```
cmd/gateway/
internal/
  oauth/     protocol only        keys/      rotation, JWKS
  oidc/      discovery, userinfo  session/   login/consent challenges
  identity/  users, credentials   rbac/      permission evaluation
  proxy/     reverse proxy        store/     postgres + redis
pkg/
  tokenvalidator/                 JWT/JWKS validation
```

Postgres holds refresh token families, clients, users and consent. Redis holds
only what is genuinely ephemeral: authorization codes, challenges, rate-limit
buckets, the access token denylist. Refresh families are deliberately *not* in
Redis — losing them makes reuse detection fail silently, which is the failure
mode where a stolen token starts working.

## Requirements

- **Go 1.26.6 or newer.** This is a security floor, not a language-feature one:
  it comes from the `moat/redisstore` dependency, which reaches `crypto/tls` and
  `encoding/asn1`. It is 1.26.6 rather than 1.25.13 because Go orders versions
  across release lines, so a 1.25.13 floor is satisfied by 1.26.5, which carries
  neither fix.
- **Redis with `maxmemory-policy: noeviction`.** Under any eviction policy, Redis
  discards rate-limit buckets without knowing what they are — and preferentially
  discards the bucket of the client already being throttled, which by making no
  requests is the best candidate under any recency- or TTL-based policy. The
  gateway asserts this at startup and refuses to start when it cannot be
  verified.
- **Postgres 16+.**

```bash
docker compose up      # gateway, Postgres, Redis, resource server
```

## Testing

```bash
go test -race ./...
go test -tags=integration -race ./...   # real Postgres and Redis, via testcontainers
go test -fuzz=FuzzParseToken -fuzztime=60s ./pkg/tokenvalidator
```

Requirements that apply to a *class* of points — every credential route carries
`no-store`, every rejection carries the security headers — are tested by
enumerating those points from code rather than from a hand-written list. A list
goes stale at the next route added, and that is how a closed class quietly
reopens.

## Dependencies

Edge security comes from [`moat`](https://github.com/JonasBorgesLM/moat), a
first-party middleware library: rate limiting, CSRF, security headers, trusted
proxy resolution, redacted secret types.

That is a deliberate and slightly uncomfortable choice, so it is stated plainly:
`moat` is pre-1.0, has not been independently audited, and has a bus factor of
one. Its `ratelimit.Store` interface took a breaking rename in a minor release,
and one published satellite tag did not compile. It is therefore **pinned to an
exact version and never auto-upgraded**; upgrades are manual and verified from a
clean directory. The reasoning is in
[`doc/adr/0011-moat-dependency.md`](doc/adr/0011-moat-dependency.md).

Where the boundary sits is documented rather than assumed. `moat` does not do
exact `redirect_uri` matching (it declines OAuth-shaped rules by design), does
not rotate session identifiers (only CSRF tokens), and does not set server
timeouts. Those are this project's job, and each has its own requirement.

## Known limitations

Stated up front, because they matter more than the feature list.

- **Not audited, not production software.** It implements well-understood
  patterns carefully; that is not a guarantee.
- **No MFA in the MVP.** Password plus PKCE is not sufficient authentication for
  anything valuable.
- **No sender-constrained tokens.** A stolen access token is usable by whoever
  holds it until it expires. DPoP and mTLS binding are planned extensions.
- **No dynamic client registration.** Clients are configured statically.
- **`Clear-Site-Data` on logout is defence in depth**, not the mechanism — it is
  ignored on non-secure origins and browser support is uneven. Server-side
  invalidation is what actually ends the session.
- **The Redis eviction check is a snapshot** taken at construction, and in cluster
  mode only reaches the masters available at that moment. A policy changed during
  a memory incident is not covered.

## Roadmap

- [ ] 0 — Foundations: ADRs, schema, CI
- [ ] 1 — Identity: hashing, constant-work login, session
- [ ] 2 — Authorization code + PKCE
- [ ] 3 — Key rotation and JWKS
- [ ] 4 — Refresh rotation, reuse detection, revocation
- [ ] 5 — RBAC
- [ ] 6 — Reverse proxy
- [ ] 7 — Full OIDC
- [ ] 8 — `client_credentials`, introspection, hardening

## License

MIT — see [LICENSE](LICENSE).
