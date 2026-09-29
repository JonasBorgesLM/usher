# Requirements — Authorization Gateway

**Version:** 0.3
**Status:** baseline for implementation — no code written yet
**Verified against:** `moat` core (`go 1.24`, no external requires) and `moat/redisstore v0.2.2` (`go 1.26.6`)

This document is binding. Every `RF-`, `RS-` and `RNF-` identifier below is
referenced from commit messages, ADRs and tests. A requirement without a test
that fails when the protection is removed counts as unimplemented.

---

## 1. Purpose

Build, from scratch, an **OAuth 2.1 / OpenID Connect Authorization Server** that
also acts as a **reverse proxy** in front of resource servers.

The primary goal is the study of secure development. This is not a replacement
for Keycloak, Hydra or Auth0, and is not intended for production. Every decision
is written down and justified — the reasoning is part of the deliverable, in the
same spirit as [`moat`](https://github.com/JonasBorgesLM/moat)'s `doc/DESIGN.md`.

The secondary goal is to be `moat`'s first real consumer under protocol load.
Several of that library's APIs were designed against an imagined consumer; this
project turns that into evidence.

### 1.1 Non-goals

Stated explicitly to bound the scope:

- Not a production IdP; no OpenID certification.
- No Dynamic Client Registration (RFC 7591).
- No federation or social login.
- No MFA in the MVP (planned extension, §11).
- No rich user management beyond what authentication requires.
- Not a substitute for TLS, secrets management, or least-privilege infrastructure.

---

## 2. Actors

| Actor | Role |
|---|---|
| Resource Owner | End user who authenticates and grants consent |
| Client | Registered application requesting tokens |
| Authorization Server (AS) | Issues codes, tokens and ID tokens; publishes discovery and JWKS |
| Resource Server (RS) | Protected service behind the gateway |
| Gateway | Edge: defenses, token validation, identity propagation, forwarding |

**Key decision:** AS and Gateway run in the same binary for the MVP, with rigid
package boundaries — the protocol package does not import the proxy package or
vice versa. This keeps the option of splitting them later without structural
rework. Recorded as ADR-01.

---

## 3. MVP scope

### 3.1 Grant types

| Grant | MVP | Rationale |
|---|---|---|
| `authorization_code` + PKCE | Yes | Central flow; highest density of real pitfalls |
| `refresh_token` with rotation | Yes | Where reuse detection and revocation live |
| `client_credentials` | Phase 8 | Service-to-service through the gateway |
| `implicit` | No | Removed from OAuth 2.1 |
| `password` (ROPC) | No | Removed from OAuth 2.1 |

Dropping the last two is not an incomplete OIDC implementation — it follows
current practice.

### 3.2 Endpoints

**Protocol:** `/.well-known/openid-configuration`, `/.well-known/jwks.json`,
`GET /authorize`, `POST /token`, `GET /userinfo`, `POST /revoke` (RFC 7009),
`POST /introspect` (RFC 7662).

**Login/Consent**, decoupled from the protocol via an opaque challenge id:
`/login`, `/consent`, `/logout`.

**Gateway:** `/api/**` (proxied), `/healthz`, `/readyz`.

---

## 4. Functional requirements

**RF-01 — Static client registration.** Clients are registered through versioned
configuration. Each declares `client_id`, type (public/confidential), hashed
`client_secret` when confidential, an exact list of `redirect_uris`, allowed
`grant_types` and `scopes`, and whether explicit consent is required.

**RF-02 — Authorization Code Flow with PKCE.** `/authorize` validates parameters,
creates a pending authorization request and redirects to `/login` with an opaque
challenge id. After authentication and consent, it issues the code and redirects
to the registered `redirect_uri`.

**RF-03 — Token issuance.** `access_token` (JWT), `refresh_token` (opaque), and
`id_token` (JWT) when the scope includes `openid`.

**RF-04 — Refresh rotation with reuse detection.** Each use invalidates the
previous token. Replaying a consumed refresh token revokes the entire family.

**RF-05 — RBAC.** Effective permission is the **intersection** of the scopes
granted to the client and the permissions of the user's role.

**RF-06 — Revocation.** `/revoke` accepts access or refresh tokens. Revoking a
refresh token revokes its family. Administrative revocation by user ends all
sessions.

**RF-07 — Tiered rate limiting.** Credential routes are limited far more
aggressively than proxied reads.

**RF-08 — Reverse proxy with identity propagation.** After validating the token,
the gateway forwards to the RS preserving the original `Authorization` header and
adding gateway-controlled identity headers.

**RF-09 — Audit.** Authentication events are recorded in structured, queryable
form.

---

## 5. Security requirements

### 5.1 Authorization flow

**RS-01 — PKCE mandatory for every client**, confidential included.
`code_challenge_method=S256` only; `plain` is rejected. A request without
`code_challenge` is rejected before any other processing.

**RS-02 — Exact string match on `redirect_uri`.** No prefix match, no wildcard, no
"helpful" normalization. Prefix matching is the classic source of open redirect
in this flow.

> No library support, by the library's decision. `moat`'s `validate.URL` covers
> scheme allow-listing and rejects scheme-relative `//host`, which is useful when
> validating client *registration*. Exact `redirect_uri` matching is explicitly
> out of scope there — it is a rule about a protocol, not about input. This
> comparison belongs to the gateway.

**RS-03 — `state` required and validated.** The anti-CSRF parameter of the OAuth
redirect, distinct from form CSRF (RS-12a).

**RS-04 — Single-use authorization code, TTL ≤ 60s.** Bound to `client_id`,
`redirect_uri` and `code_challenge`, all three re-verified at `/token`. **Replay
of a consumed code revokes every token issued from it** — replay indicates
interception, not client error.

**RS-05 — Challenge isolation.** The challenge id is opaque, high-entropy,
single-use and short-lived. It carries no request parameters in the query string.

### 5.2 Tokens

**RS-06 — Asymmetric algorithms with a verification allow-list.** RS256 or ES256.
The accepted algorithm set is fixed at validator construction: `alg: none`
rejected, HS256 rejected where RS256 is expected (key confusion, where the public
key is used as the HMAC secret). The token's own `alg` header never selects the
verification method.

**RS-07 — Full claim validation.** `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`,
`typ`. Clock skew is configurable and measured in seconds, never minutes. Access
tokens carry `typ: at+jwt` (RFC 9068).

**RS-08 — Strict separation of ID token and access token.** ID token: `aud` =
client, consumed by the client, never accepted as an API credential. Access
token: `aud` = resource server, the only credential the gateway accepts.
Presenting an ID token to the gateway must produce 401.

**RS-09 — Key rotation without downtime.** Every JWT carries `kid`. A new key is
published in the JWKS before it signs. The old key stays published for at least:

```
max_access_token_TTL + clock_skew + consumer_JWKS_cache_TTL
```

The third term is the one that gets forgotten and the one that causes the outage;
it must be explicit configuration, not a constant in code. Refetch triggered by
an unknown `kid` is rate limited — otherwise an attacker sending tokens with
random `kid` turns the resource server into a DoS amplifier against the AS.

**RS-10 — Opaque refresh tokens stored hashed.** ≥256 bits from `crypto/rand`,
persisted as SHA-256, looked up by hash. A database dump must not yield usable
tokens.

**RS-11 — Reuse detection with family revocation.** Each session has a
`family_id`. A consumed refresh token reappearing invalidates the whole family
and raises a high-severity audit event. The "already consumed" check is
**atomic** (compare-and-set), never read-then-write.

### 5.3 Credentials

**RS-12a — CSRF on browser forms, and only there.** `/login` and `/consent`
(POST) require a CSRF token. `/token`, `/introspect` and `/revoke` do not — they
are server-to-server endpoints with no cookie, and applying CSRF there breaks the
protocol for no benefit.

**RS-12b — Rotate both the CSRF token and the session id on login.** Two distinct
rotations, and doing only one is the likely failure. `moat`'s `csrf.Rotate`
covers the CSRF half of session fixation; it does not rotate the session
identifier, and the library documents this precisely because calling `Rotate` at
login *looks* like it solves both. Session id rotation belongs to the gateway.
One test per half. `Rotate` returns `ErrHeadersAlreadySent` if called after the
response has started — handle it, never ignore it.

**RS-13 — GPU-resistant password hashing.** Argon2id preferred, or bcrypt with a
calibrated cost. Parameters are versioned per record, enabling transparent rehash
on the next successful login.

**RS-14 — Constant work on login, against user enumeration.** Three surfaces
closed together: **timing** (verify against a precomputed dummy hash when the
user does not exist), **message** (identical response either way), and **rate
limiting** (the per-account axis must not distinguish an existing account from a
non-existent one, or the oracle returns through the back door).

**RS-15 — Secrets held in `secret.Value`.** Client secrets, authorization codes
and opaque tokens use `moat`'s `secret.Value`, which provides constant-time
comparison and redaction across every formatting path. Direct comparison with
`==` or `bytes.Equal` is forbidden; the type makes this hard by construction.

**RS-16 — Client authentication.** Confidential clients use
`client_secret_basic` or `client_secret_post`, with the secret stored hashed and
compared in constant time. Public clients rely on PKCE alone — PKCE does not turn
a public client into a confidential one.

### 5.4 Gateway

**RS-17 — Strip inbound identity headers.** The gateway removes from every
inbound request any header in the identity namespace it produces (`X-Auth-*`)
*before* injecting its own. Implement as an allow-list of what passes through,
not a block-list of what is stripped. Without this, a client sends the header and
becomes whoever it wants.

**RS-18 — Defence in depth: the RS re-validates.** The original token is
forwarded and the resource server independently validates signature, `aud` and
`exp` against the JWKS. It does not trust "it came from the gateway, therefore it
is authenticated" — the internal network is not a trust boundary.

**RS-19 — Audience-restricted tokens.** A token issued for one resource server is
not accepted by another behind the same gateway.

**RS-20 — Hop-by-hop headers and upstream responses.** Stripped in both
directions. A custom `ErrorHandler` on `httputil.ReverseProxy` ensures an
upstream failure leaks no stack trace, internal hostname or topology detail.
Upstream redirects are not followed automatically.

**RS-21 — Explicit timeouts everywhere.** `ReadHeaderTimeout` (Slowloris),
`ReadTimeout`, `WriteTimeout`, `IdleTimeout` on the server; timeout and response
size limit on the upstream client. The `net/http` default is "no timeout".

**RS-22 — Two-axis rate limiting.** Per IP **and** per account. IP alone does not
survive distributed credential stuffing; account alone lets an attacker lock
someone else out. The IP axis uses `moat`'s middleware with `realip`; the account
axis uses `Limiter.Allow`/`AllowN` called inside the handler, once identity is
known. `AllowN` carries weighted cost — `/token` is heavier than a GET.

### 5.5 Leakage and observability

**RS-23 — No secrets in logs.** Tokens, codes, `code_verifier`, secrets and
passwords never appear in a log line, error message or trace span. Types carrying
secrets use `secret.Value`. Accepted inherited limitation: anything able to read
process memory recovers the values — the guarantee covers accidental printing,
not an in-process attacker.

**RS-24 — Tokens never in query strings.** They leak through proxy logs, browser
history and `Referer`.

**RS-25 — Errors per RFC 6749 §5.2.** Fixed codes, no internal detail.
`invalid_grant` deliberately covers several distinct cases; that ambiguity is a
security property, not a lack of clarity.

**RS-26 — `Cache-Control: no-store` on credential responses.**
`secureheaders.NoStore`, applied **per route**: `/token`, `/userinfo`,
`/introspect` and anything carrying an identity claim. `no-store`, not
`no-cache` — the latter lets a shared cache retain the response and merely
revalidate, leaving a token in a proxy.

**RS-27 — `Clear-Site-Data` on logout.** `secureheaders.ClearSiteData`, per
route. Two inherited caveats matter here: it is ignored on non-secure origins and
support is uneven, so it is defence in depth over real server-side invalidation,
never the mechanism; and clearing `cookies` reaches the whole registrable domain,
not the origin — decide and document whether that is intended.

---

## 6. Non-functional requirements

**RNF-01 — Go 1.26.6 floor.** This is the `redisstore` satellite's floor, and it
is a *security* floor rather than a language-feature one: that module reaches
`crypto/tls` and `encoding/asn1`, which carry GO-2026-6090 and GO-2026-5972,
fixed in 1.26.6. It is 1.26.6 rather than 1.25.13 because Go orders versions
across release lines, so a 1.25.13 floor is satisfied by 1.26.5, which has
neither fix. The `moat` core alone requires only Go 1.24.

**RNF-02 — Minimal external dependencies**, each justified by an ADR.

**RNF-03 — Configuration from environment and versioned files.** Secrets never in
the repository.

**RNF-04 — Fail closed** on every authorization decision. Infrastructure failure
denies.

**RNF-05 — Fail loudly at startup** rather than starting degraded. There is a
test that boots the application with incomplete configuration and requires it not
to start.

**RNF-06 — `docker compose up`** brings up gateway, Postgres, Redis and the
resource server in one command.

**RNF-07 — Redis with `maxmemory-policy: noeviction`, asserted at startup.** Not
tuning: a Redis under `maxmemory` with any eviction policy discards rate-limit
buckets without knowing what they are, and preferentially discards the bucket of
the client already being throttled — which, by making no requests, is the best
candidate under any recency- or TTL-based policy.

The gateway asserts this at startup rather than assuming it:

```go
if check := store.EvictionCheck(); !check.Verified() {
    return fmt.Errorf("redis eviction policy unverified: %s", check)
}
```

`redisstore` returns `ErrUnsafeEvictionPolicy` when it can prove the policy is
unsafe, but the check is skipped silently when `CONFIG` is unavailable — the
normal case on ElastiCache, MemoryDB, Upstash and Azure Cache. `EvictionCheck()`
is what distinguishes *verified safe* from *not checked*, and RNF-05 requires the
gateway to treat the second as a startup failure rather than a shrug.

Two gaps a verified result does not close, both accepted and documented: it is a
snapshot of mutable server state taken once at construction, and in cluster mode
only the masters reachable at that moment are consulted.

---

## 7. Architecture

```
cmd/gateway/
internal/
  oauth/          protocol only (authorize, token, revoke, introspect)
    grant/        one Strategy per grant_type
  oidc/           discovery, id_token, userinfo
  keys/           generation, rotation, JWKS, cache
  session/        login and consent challenges, user session
  identity/       users, credentials, roles
  rbac/           permission evaluation
  proxy/          reverse proxy and identity propagation
  store/
    postgres/     source of truth
    redis/        rate limits, ephemeral challenges, denylist
pkg/
  tokenvalidator/ JWT/JWKS validation (see §7.4)
doc/
  DESIGN.md       security reasoning
  adr/            architectural decisions
```

### 7.1 Storage split

| Data | Where | Why |
|---|---|---|
| Clients, users, roles | Postgres | Durable source of truth |
| Refresh token families | **Postgres** | Data loss means reuse detection fails silently |
| Granted consent | Postgres | Auditable |
| Authorization codes | Redis | TTL ≤ 60s |
| Login/consent challenges | Redis | Ephemeral |
| Rate limit buckets | Redis | Shared across instances (see RNF-07) |
| Access token denylist | Redis | TTL equals token TTL |
| Private keys | Outside the database | Mounted file or KMS |

### 7.2 Middleware pipeline

Order, in every chain:
`secureheaders` → `ratelimit` → `validate.MaxBodyBytes` → `[csrf]` → `[auth]` →
`[rbac]` → handler.

Headers outermost so that 401, 403 and 429 carry them too. The body limit
precedes CSRF because CSRF parses form-encoded bodies.

| Route group | csrf | auth | rbac | Rate limit |
|---|---|---|---|---|
| `/.well-known/*`, JWKS | no | no | no | permissive, cached |
| `/authorize` | no | session | no | moderate |
| `/login`, `/consent` (POST) | **yes** | — | no | **strict**, two axes |
| `/token`, `/revoke`, `/introspect` | **no** | client auth | no | **strict**, weighted `AllowN` |
| `/api/**` | no | bearer | yes | per token/account |

**On `preset.API`:** it is now a defensible option. It requires the proxy
topology to be declared (`TrustedProxies` or `DirectlyExposed`) instead of
silently giving every client one shared bucket, and `DisableCSRF: true` is
explicit and greppable. Explicit composition remains the MVP choice because the
`/authorize` and `/api/**` chains are not modelled by the preset. Recorded as
ADR-06 — a choice between two valid options, not a rejection.

### 7.3 Responsibility boundary with `moat`

| Requirement | `moat` provides | The gateway still does |
|---|---|---|
| RS-02 | `validate.URL` (scheme, rejects `//host`) | Exact match against registered `redirect_uris` |
| RS-12a | `csrf`: signed double-submit, Origin/Referer, `__Host-` | Apply only on browser routes |
| RS-12b | `csrf.Rotate` — the CSRF half of fixation | Rotate the **session id** |
| RS-15, RS-23 | `secret.Value` | Use it for every secret, not just the obvious ones |
| RS-17 | — | Entirely the gateway's |
| RS-21 | — | Entirely the gateway's (`http.Server` config, not middleware) |
| RS-22 | `realip` + `Limiter.Allow`/`AllowN` | Choose keys and weights; keep the account axis from becoming an oracle (RS-14) |
| RS-26 | `secureheaders.NoStore` | Apply on the right routes |
| RS-27 | `secureheaders.ClearSiteData` | Real server-side invalidation |
| RNF-07 | `Store.EvictionCheck()` | Assert `Verified()` at startup and fail |
| CSP | Per-request nonce + `Nonce(r)` | Use it in login/consent templates; handle `WithNonceErrorHandler` |

**`realip` topology, both sides.** The gateway is the trusted proxy for the
resource server and may itself sit behind a load balancer. Two separate
configurations, and getting either wrong silently disables rate limiting: the
gateway declares the CIDRs of the balancer in front of it (or declares direct
exposure); the resource server declares the gateway's CIDR. An empty trust set is
a construction error, and so is `0.0.0.0/0` — the latter matters most here,
because it is the easy way out for someone who does not know the balancer's
range. Recorded as ADR-10.

**Trust decision.** `moat` is a first-party, pre-1.0, independently unaudited
dependency. It is pinned to an exact version and never auto-upgraded: its
`ratelimit.Store` interface took a breaking rename in a minor release, and a
published satellite tag once did not compile. Upgrades are manual, with a build
verified from a clean directory. Recorded as ADR-11 — the reasoning matters more
than the conclusion.

**ADRs cite properties, not the library.** An ADR states *"the rate-limit key
derives from the first untrusted peer, so a forged `X-Forwarded-For` cannot
control it"* and notes that `moat` supplies it today. If the library changes or
is replaced, the requirement outlives the dependency.

### 7.4 `pkg/tokenvalidator`

`moat` has recorded a decision **not** to extract a `jwtauth` module, with an
explicit reopening criterion: the signature must have stabilized under real use,
measured by how often it changed across the consumer's recent iterations and
whether a second consumer informed the design. That criterion currently fails for
lack of any measurement — no validator is in use.

This project produces the measurement. Practical consequence: **record
`tokenvalidator`'s public signature changes at the end of every phase.** That
count is the evidence the criterion asks for; without the record, the future
re-evaluation depends on memory.

---

## 8. Patterns

| Pattern | Where | Why |
|---|---|---|
| Chain of Responsibility | HTTP pipeline | Explicit, auditable order |
| Strategy | `grant/` | One handler per `grant_type` |
| Template Method | `TokenIssuer` | Shared skeleton, per-grant variation |
| Repository | `store/` | Swap backends without touching business rules |
| Decorator | RBAC | `RequirePermission("task:write")(handler)` |
| Facade | `/token` handler | Dispatches to the right Strategy |

Field validation lives in the service layer, not in handlers or middleware.

---

## 9. Technology

| Need | Choice | Considered |
|---|---|---|
| HTTP | `net/http` + `chi` | Works with `moat` without an adapter |
| Edge security | `moat` + `moat/redisstore` | — |
| JOSE / JWKS | `lestrrat-go/jwx/v4` | `golang-jwt/jwt/v5` — leaner, weaker JWK support |
| Password hashing | `golang.org/x/crypto/argon2` | `bcrypt` |
| Postgres | `pgx/v5` | — |
| Redis | `go-redis/v9` | Already a `redisstore` dependency |
| Migrations | `golang-migrate` | — |
| Integration tests | `testcontainers-go` | Consistent with `moat` |

`ory/fosite` is read as an architectural reference for what a correct OAuth2
implementation requires. Read, not imported — the value of this project is in
implementing it.

---

## 10. Testing strategy

- **Unit tests** for pure business rules.
- **Negative security tests with a negative control.** Each `RS-` has a test that
  attempts the attack; each test is then validated by removing the protection and
  confirming the test fails. Without that second step, a test that passes against
  both implementations creates confidence without a guarantee.
- **Integration** (`-tags=integration`): real Postgres and Redis via
  testcontainers, full flow end to end.
- **Fuzzing** of protocol parameter and JWT parsing. Property: no malformed input
  ever produces an accepted token.
- **Timing**: statistical comparison of login latency for existing versus
  non-existent users. Non-deterministic; a regression signal, not a CI gate.
- **Concurrency**: `-race` always, plus a test where simultaneous refresh
  exchanges yield exactly one issuance.
- **Properties, not instances.** Where a requirement applies to a *class* of
  points — every credential route carries `no-store`, every rejection carries the
  security headers — the test enumerates those points from code, not from a
  hand-written list. A hand-written list goes stale at the next point added, and
  that is how a closed class reopens.
- **README examples run in CI.** The first snippet a visitor copies must compile.

---

## 11. Phases

| Phase | Delivery |
|---|---|
| 0 | This document, ADRs, schema, package skeleton, CI |
| 1 | Identity: users, hashing, constant-work login, session, dual rotation |
| 2 | Authorization code + PKCE, `/authorize`, `/token`, login/consent challenge |
| 3 | Keys: generation, `kid`, JWKS, rotation, background-refresh cache |
| 4 | Refresh rotation, reuse detection, revocation, `/revoke` |
| 5 | RBAC and scope intersection |
| 6 | Gateway: reverse proxy, header stripping, RS re-validation |
| 7 | Full OIDC: `id_token`, `/userinfo`, discovery, logout |
| 8 | `client_credentials`, `/introspect`, hardening |
| — | Extensions: MFA (TOTP), sender-constrained tokens (DPoP/mTLS), back-channel logout |

---

## 12. ADRs to record before phase 1

1. AS and gateway in one binary, rigid package boundaries
2. Postgres as the source of truth for refresh families
3. Fail-closed rate limiting; `noeviction` as an infrastructure requirement
4. `jwx/v4` over `golang-jwt`
5. Argon2id with versioned parameters
6. Explicit composition versus two `preset.API` chains
7. Original token forwarded; the RS re-validates
8. Go floor at 1.26.6, inherited from the `redisstore` satellite
9. Per-phase record of `tokenvalidator` signature changes
10. `realip` topology — who trusts whom, on both sides
11. Trust decision for the first-party `moat` dependency

---

## 13. MVP acceptance

The MVP is complete when a registered client completes the full flow —
`/authorize` → login → consent → code → `/token` → authenticated call through the
gateway → refresh → revocation — and every negative test in §10 fails as
expected, with each `RS-` covered by at least one test validated by a negative
control.
