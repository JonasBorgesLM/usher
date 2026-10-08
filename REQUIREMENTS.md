# Requirements — usher

**Version:** 0.6
**Status:** baseline for implementation — no code written yet
**Verified against:** `moat` core `v0.2.0` (`go 1.24`, no external requires),
`moat/redisstore v0.2.2` (`go 1.26.6`), `bastion v0.2.1` (`go 1.24`). Every
`moat` API named below was checked to exist at those tags, not at `main`.
**Companion documents:** [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) ·
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`docs/adr/`](docs/adr/README.md)

This document is binding. Every `RF-`, `RS-`, `RNF-` and `RI-` identifier below
is referenced from commit messages, ADRs and tests.

> **A requirement without a test that fails when the protection is removed
> counts as unimplemented.**

Cross-project citations are written qualified — `bastion/ADR-0009`,
`crier/IR7` — so they are not silently checked against this project's numbering.
What changed from v0.3, and why, is in [§15](#15-changes-from-v03); from v0.4, in
[§16](#16-changes-from-v04); from v0.5, in [§17](#17-changes-from-v05).

---

## 1. Purpose

Build, from scratch, an **OAuth 2.1 / OpenID Connect Authorization Server** that
also acts as a **reverse proxy** in front of resource servers.

The primary goal is the study of secure development. This is not a replacement
for Keycloak, Hydra or Auth0, and is not intended for production. Every decision
is written down and justified — the reasoning is part of the deliverable, in the
same spirit as [`moat`](https://github.com/JonasBorgesLM/moat)'s `doc/DESIGN.md`.

The secondary goal is to be the first real consumer, under protocol load, of the
libraries in this ecosystem: `moat` (edge security) and `bastion` (outbound
resilience). Several of their APIs were designed against an imagined consumer;
this project turns that into evidence. It is also the audit-event source `crier`
was designed around (`crier/IR3`), and the target that `warden` and `sapper`
verify (RI-06).

The baseline reference for protocol security is **RFC 9700** (OAuth 2.0
Security Best Current Practice) together with the OAuth 2.1 draft. Where this
document is stricter, it says so.

### 1.1 Non-goals

Stated explicitly to bound the scope. Each names who owns it instead.

- Not a production IdP; no OpenID certification. *Use Keycloak, Hydra or a hosted IdP.*
- No Dynamic Client Registration (RFC 7591). *Clients are static configuration (RF-01).*
- No federation or social login. *Out of scope for a study of the core flow.*
- No MFA in the MVP. *Planned extension, §11.*
- No `private_key_jwt`, mTLS client authentication, PAR (RFC 9126) or JAR
  (RFC 9101). *Planned extensions; `client_secret_*` covers the MVP (RS-16).*
- No rich user management beyond what authentication requires. *Users are seeded.*
- No shared cache in front of any authorization decision. `cistern` exists in
  this ecosystem and is deliberately **not** used: nothing in the MVP has a read
  path worth caching, and a cached authorization decision is a revocation
  bypass with a TTL.
- Not a substitute for TLS, secrets management, or least-privilege
  infrastructure. *The operator's; the gateway refuses to start where it can
  detect the gap (RNF-05, RNF-07).*

---

## 2. Actors

| Actor | Role | Assumed capability | Assumed *not* to have |
|---|---|---|---|
| Resource Owner | End user who authenticates and grants consent | A browser; may be phished or on a hostile network | The server's secrets |
| Client | Registered application requesting tokens | Its own `client_id`; its secret if confidential | Another client's secret; the ability to register redirect URIs at runtime |
| Authorization Server (AS) | Issues codes, tokens and ID tokens; publishes discovery and JWKS | The signing keys | — |
| Resource Server (RS) | Protected service behind the gateway | The public JWKS | Any private key; any trust in the network path (RS-18) |
| Gateway | Edge: defenses, token validation, identity propagation, forwarding | The same binary as the AS (ADR-0001) | A reason to trust inbound identity headers (RS-17) |
| Attacker | See the threat model | Any request any client can send; replay of anything that leaked | The signing keys; a TLS break |

**Key decision:** AS and Gateway run in the same binary for the MVP, with rigid
package boundaries — the protocol package does not import the proxy package or
vice versa. This keeps the option of splitting them later without structural
rework. Recorded as [ADR-0001](docs/adr/0001-one-binary-rigid-package-boundaries.md),
and asserted in CI rather than trusted (RNF-08).

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
`/login`, `/consent`, `/logout`. Server-rendered with `html/template`; there is
no JavaScript application.

**Gateway:** `/api/**` (proxied), `/healthz`, `/readyz`.

---

## 4. Functional requirements

**RF-01 — Static client registration.** Clients are registered through versioned
configuration. Each declares `client_id`, type (public/confidential), hashed
`client_secret` when confidential, an exact list of `redirect_uris`, allowed
`grant_types` and `scopes`, the audiences it may request, and whether explicit
consent is required. Registration is validated at startup (RNF-05): a
`redirect_uri` that is not absolute, uses a scheme outside the allow-list, or
carries a fragment is a configuration error.

**RF-02 — Authorization Code Flow with PKCE.** `/authorize` validates parameters
in the order RS-28 fixes, creates a pending authorization request and redirects
to `/login` with an opaque challenge id. After authentication and consent, it
issues the code and redirects to the registered `redirect_uri` with `code`,
`state` and `iss` (RS-29).

**RF-03 — Token issuance.** `access_token` (JWT), `refresh_token` (opaque), and
`id_token` (JWT) when the scope includes `openid`. Which of these each phase
issues is in §11 — the phases deliver them incrementally.

**RF-04 — Refresh rotation with reuse detection.** Each use invalidates the
previous token. Replaying a consumed refresh token revokes the entire family.
There is no grace window for a concurrent or retried request
([ADR-0012](docs/adr/0012-strict-refresh-rotation-no-grace-window.md)).

**RF-05 — RBAC.** Effective permission is the **intersection** of the scopes
granted to the client and the permissions of the user's role.

**RF-06 — Revocation.** `/revoke` accepts access or refresh tokens. Revoking a
refresh token revokes its family. Administrative revocation by user ends all
sessions and families. **Scope of the guarantee:** a revoked access token is
refused by the gateway from the next request; a resource server validating
independently (RS-18) keeps accepting it until `exp`. The access token TTL is
therefore the revocation bound at the RS, and RF-12 caps it for that reason
([ADR-0014](docs/adr/0014-access-token-revocation-is-gateway-local.md)).

**RF-07 — Tiered rate limiting.** Credential routes are limited far more
aggressively than proxied reads.

**RF-08 — Reverse proxy with identity propagation.** After validating the token,
the gateway forwards to the RS preserving the original `Authorization` header and
adding gateway-controlled identity headers (RI-04).

**RF-09 — Audit.** Authentication events — login success and failure, consent,
token issuance, refresh reuse detected, revocation, rate-limit rejection, token
rejected at the gateway — are recorded as structured events with a versioned
schema. Where they go is RI-03.

**RF-10 — Browser session at the AS.** A successful login establishes a
server-side session, so a second `/authorize` from the same browser does not
re-prompt within its lifetime. Its security properties are RS-31.

**RF-11 — OIDC request parameters.** `nonce` (RS-30), `prompt=none` and
`prompt=login`, and `max_age` (with `auth_time` in the ID token) are supported.
Any other `prompt` value is rejected with `invalid_request`; unrecognised
parameters are ignored, as RFC 6749 §3.1 requires.

**RF-12 — Lifetimes are bounded configuration.** Every lifetime is configurable
within a hard upper bound; a value above the bound is a startup error (RNF-05),
not a warning.

| Lifetime | Default | Upper bound | Why the bound |
|---|---|---|---|
| Authorization code | 60 s | 60 s | RS-04 |
| Login/consent challenge | 5 min | 15 min | RS-05 |
| Access token | 5 min | 15 min | It is the revocation bound at the RS (RF-06) |
| Refresh token, idle | 24 h | 7 d | — |
| Refresh family, absolute | 7 d | 30 d | A family must end even if continuously used |
| Browser session, idle / absolute | 30 min / 12 h | 2 h / 24 h | RS-31 |

**RF-13 — Consent is recorded and revocable.** Granted consent is stored per
`(user, client, scope set)`. A request for a scope not previously granted
prompts again. Revoking consent revokes the refresh families issued under it.

---

## 5. Security requirements

### 5.1 Authorization flow

**RS-01 — PKCE mandatory for every client**, confidential included.
`code_challenge_method=S256` only; `plain` is rejected, and so is a request
without `code_challenge`. *Where* that rejection is delivered depends on whether
the client and `redirect_uri` have already been validated — RS-28 fixes the
order. (v0.3 said "before any other processing", which is incompatible with
RS-28: an error cannot be redirected safely before the redirect target is
known.)

**RS-02 — Exact string match on `redirect_uri`.** No prefix match, no wildcard, no
"helpful" normalization. Prefix matching is the classic source of open redirect
in this flow.

> No library support, by the library's decision. `moat`'s `validate.URL` covers
> scheme allow-listing and rejects scheme-relative `//host`, which is useful when
> validating client *registration* (RF-01). Exact `redirect_uri` matching is
> explicitly out of scope there — it is a rule about a protocol, not about input.
> This comparison belongs to the gateway.

**RS-03 — `state` required and validated.** The anti-CSRF parameter of the OAuth
redirect, distinct from form CSRF (RS-12a). Returned unchanged.

**RS-04 — Single-use authorization code, TTL ≤ 60s, consumed atomically.**
Bound to `client_id`, `redirect_uri`, `code_challenge` and, when present,
`nonce`; all re-verified at `/token`. Consumption is **one atomic operation**
(compare-and-set, as RS-11 requires of refresh tokens): two concurrent exchanges
of the same code yield exactly one issuance. v0.3 required atomicity only of
refresh consumption, and a read-then-delete on the code is the same race.

**Replay of a consumed code revokes every token issued from it** — replay
indicates interception, not client error. To make that possible, consumption
leaves a tombstone linking the code to the family it created, retained for the
access token's maximum lifetime.

*Residual, stated:* a replay after the tombstone expires, or after Redis loses
it, is an ordinary `invalid_grant` with no revocation. The detection window is
bounded; the single-use property is not.

**RS-05 — Challenge isolation.** The challenge id is opaque, high-entropy,
single-use and short-lived (RF-12). It carries no request parameters in the
query string.

**RS-28 — `/authorize` validation order; never redirect to an unverified
target.** The order is the requirement, because code with the steps reversed
looks identical:

1. `client_id` is known — otherwise render an error page, **no redirect**.
2. `redirect_uri` exactly matches a registered one (RS-02) — otherwise render an
   error page, **no redirect**.
3. Everything else — `response_type`, PKCE (RS-01), `state` (RS-03), scope — is
   reported to the now-verified `redirect_uri` as an RFC 6749 §4.1.2.1 error.

Redirecting an error for an unverified `redirect_uri` is an open redirect with an
error message attached. The test asserts the order with a request that fails
steps 2 and 3 at once, and requires the non-redirecting response.

**RS-29 — Authorization responses carry `iss` (RFC 9207).** Every redirect from
`/authorize`, success or error, includes `iss`, and discovery advertises
`authorization_response_iss_parameter_supported: true`. This is the mitigation
for mix-up attacks against clients that talk to more than one AS; it costs one
parameter.

**RS-30 — `nonce` is bound and echoed.** When the request carries `nonce`, it is
stored with the code (RS-04) and returned unchanged in the ID token. Length is
bounded. It is not required — PKCE already binds the code to the client instance
— but when a client sends it, silently dropping it disables the client's replay
check without telling it.

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
Presenting an ID token to the gateway, or to `/userinfo`, must produce 401.
`typ` is checked as well as `aud`: either alone is one misconfiguration away
from accepting the other token.

`/userinfo` is itself a protected resource. An access token issued for a request
with the `openid` scope carries the AS's userinfo audience in addition to the
resource server's; `/userinfo` accepts only tokens that carry it.

**RS-09 — Key rotation without downtime.** Every JWT carries `kid`. A new key is
published in the JWKS before it signs. The old key stays published for at least:

```
max_access_token_TTL + clock_skew + consumer_JWKS_cache_TTL
```

The third term is the one that gets forgotten and the one that causes the outage;
it must be explicit configuration, not a constant in code. Refetch triggered by
an unknown `kid` is rate limited — otherwise an attacker sending tokens with
random `kid` turns the resource server into a DoS amplifier against the AS.

Every instance must agree on which key signs at a given moment without
coordinating at runtime; how is
[ADR-0015](docs/adr/0015-signing-keyset-custody-and-rotation.md). Signing
defaults to RS256, which OpenID Connect Core requires an OP to support.

**Emergency revocation of a key** is a `kid` denylist in configuration: the key
leaves the JWKS and the gateway refuses it on the next request after restart.
A consumer validating directly keeps accepting it until its JWKS cache expires —
the same gateway-local shape as RF-06, and T-18's residual.

**RS-10 — Opaque refresh tokens stored hashed.** ≥256 bits from `crypto/rand`,
persisted as SHA-256, looked up by hash. A database dump must not yield usable
tokens.

**RS-11 — Reuse detection with family revocation.** Each session has a
`family_id`. A consumed refresh token reappearing invalidates the whole family
and raises a high-severity audit event. The "already consumed" check is
**atomic** (compare-and-set), never read-then-write. The revocation records
`revoked_reason = reuse_detected` on the family row in the same transaction, so
the fact survives any loss of the audit stream (ADR-0017).

**RS-34 — Refresh tokens are bound to their client and their grant.** The
refresh grant requires the same `client_id` the family was issued to, and client
authentication when that client is confidential. A requested `scope` must be a
subset of the original grant; asking for more is `invalid_scope`, never a
silent upgrade.

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

**RS-33 — Password hashing runs under a concurrency bound.** Argon2id is
memory-hard by design, which makes unauthenticated `/login` a memory-exhaustion
lever: fifty concurrent attempts at 64 MiB each is 3.2 GiB. Hashing runs behind
a fixed-size semaphore; the budget `concurrency × memory parameter` is checked
against a configured ceiling at startup (RNF-05). A request that cannot acquire
a slot within a bounded wait gets `503` — and that path must do the same work
for existing and non-existent accounts, or it becomes the oracle RS-14 closes.

**RS-14 — Constant work on login, against user enumeration.** Three surfaces
closed together: **timing** (verify against a precomputed dummy hash when the
user does not exist), **message** (identical response either way), and **rate
limiting** (the per-account axis must not distinguish an existing account from a
non-existent one, or the oracle returns through the back door).

**RS-35 — One canonical form of the login identifier.** The identifier is
canonicalized once — the same form used for lookup, for the per-account
rate-limit key (RS-22) and for audit. Otherwise `Alice@example.com` and
`alice@example.com` are two buckets for one account, and the account axis is
bypassed by changing case.

**RS-15 — Secrets held in `secret.Value`.** Client secrets, authorization codes
and opaque tokens use `moat`'s `secret.Value`, which provides constant-time
comparison and redaction across every formatting path. Direct comparison with
`==` or `bytes.Equal` is forbidden; the type makes this hard by construction.

**RS-16 — Client authentication.** Confidential clients use
`client_secret_basic` or `client_secret_post`, with the secret stored hashed and
compared in constant time. Client secrets are generated with ≥256 bits of
entropy, so SHA-256 is the right hash for them — a slow hash would buy nothing
against a secret that cannot be guessed, and would put the RS-33 cost on
`/token`. Public clients rely on PKCE alone — PKCE does not turn a public client
into a confidential one.

**RS-31 — The AS browser session.** The session cookie is `__Host-` prefixed,
`Secure`, `HttpOnly`, `SameSite=Lax`, and carries an opaque id of ≥256 bits;
the store holds its SHA-256, as RS-10 does for refresh tokens. The session has
the idle and absolute lifetimes of RF-12, enforced server-side. `/logout`
deletes the server-side session **before** responding; the cookie deletion and
`Clear-Site-Data` (RS-27) are the browser half, not the mechanism.

**RS-32 — Login and consent cannot be framed.** Every HTML response carries
`Content-Security-Policy: frame-ancestors 'none'`. A consent page in an invisible
frame is a clickjacking attack that grants scopes on the user's behalf.

**RS-36 — HTML is rendered only through `html/template`, under a nonce CSP.**
Login, consent and error pages render through `html/template`, and every script
runs under `moat`'s per-request CSP nonce (§7.3). Values that did not originate
in the binary — a client's registered name, requested scopes, an
`error_description` — are never wrapped in `template.HTML` or its siblings.
The consent page is where a malicious client's own registration data meets the
user's session, which makes it the page an injection would target.

### 5.4 Gateway

**RS-17 — Strip inbound identity headers.** The gateway removes from every
inbound request any header in the identity namespace it produces (`X-Auth-*`)
*before* injecting its own. Implement as an allow-list of what passes through,
not a block-list of what is stripped. Without this, a client sends the header and
becomes whoever it wants.

**RS-18 — Defence in depth: the RS re-validates.** The original token is
forwarded and the resource server independently validates signature, `aud` and
`exp` against the JWKS. It does not trust "it came from the gateway, therefore it
is authenticated" — the internal network is not a trust boundary. The resource
server in this repository makes no authorization decision from `X-Auth-*`
headers (RI-04).

**RS-19 — Audience-restricted tokens.** A token issued for one resource server is
not accepted by another behind the same gateway. Each proxied route declares the
audience it requires; a route without one is a startup error.

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
known. `AllowN` carries weighted cost — `/token` is heavier than a GET. Hitting
the account axis throttles; it never locks the account, since a lockout an
attacker can trigger is a denial of service they control.

### 5.5 Leakage and observability

**RS-23 — No secrets in logs.** Tokens, codes, `code_verifier`, secrets and
passwords never appear in a log line, error message, audit event or trace span.
Types carrying secrets use `secret.Value`. Accepted inherited limitation:
anything able to read process memory recovers the values — the guarantee covers
accidental printing, not an in-process attacker. `crier`'s redaction downstream
(RI-03) is defence in depth, not this requirement's mechanism.

**RS-24 — Tokens never in query strings.** They leak through proxy logs, browser
history and `Referer`. The authorization code in the redirect is the one
parameter the protocol puts there; its exposure is what RS-04's 60-second,
single-use, PKCE-bound shape exists to contain.

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
support is uneven, so it is defence in depth over real server-side invalidation
(RS-31), never the mechanism; and clearing `cookies` reaches the whole
registrable domain, not the origin — decide and document whether that is
intended.

---

## 6. Non-functional requirements

**RNF-01 — Go 1.26.6 floor.** This is the `redisstore` satellite's floor, and it
is a *security* floor rather than a language-feature one: that module reaches
`crypto/tls` and `encoding/asn1`, which carry GO-2026-6090 and GO-2026-5972,
fixed in 1.26.6. It is 1.26.6 rather than 1.25.13 because Go orders versions
across release lines, so a 1.25.13 floor is satisfied by 1.26.5, which has
neither fix. The `moat` core alone requires only Go 1.24. This is an
application, so the floor is an imposition inherited from a dependency, not a
promise to importers.

**RNF-02 — Minimal external dependencies**, each justified by an ADR.

**RNF-03 — Configuration from environment and versioned files.** Secrets never in
the repository.

**RNF-04 — Fail closed** on every authorization decision. Infrastructure failure
denies.

**RNF-05 — Fail loudly at startup** rather than starting degraded. There is a
test that boots the application with incomplete configuration and requires it not
to start. This covers every "startup error" named elsewhere: RF-01, RF-12,
RS-19, RS-33, RNF-07.

**RNF-06 — `docker compose up`** brings up the gateway, Postgres, Redis and the
demo resource server (RI-05) in one command.

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

**RNF-08 — The conventions are checks before phase 1.** Conventional Commits on
every commit and on the PR title, ADR immutability, requirement and threat id
resolution, relative links, the dependency allow-list (RNF-09) and the package
boundary of ADR-0001 are CI jobs — written, and each seen failing, before the
first line of production code.

**RNF-09 — Every direct dependency is on an allow-list naming its ADR.** RNF-02
made mechanical: CI asks the resolver for the direct requirements and fails on
any module the allow-list does not name. Grepping `go.mod` is not the check —
the resolver is.

**RNF-10 — Health, readiness and logs.** `/healthz` reports the process alone.
`/readyz` reports Postgres and Redis reachable, the eviction check verified
(RNF-07) and the signing keyset loaded; it is what an orchestrator gates traffic
on. Logs are structured JSON (`log/slog`) correlated by request id, under RS-23.

**RNF-11 — Graceful shutdown.** On `SIGTERM` the server stops accepting, drains
in-flight requests within a bounded deadline, then closes stores.

---

## 7. Architecture

```
cmd/
  usher/            the AS + gateway binary
  resource-server/  demo RS, validates with pkg/tokenvalidator (RI-05)
internal/
  config/           env + versioned files → Config; fails closed (RNF-03, RNF-05)
  oauth/            protocol only (authorize, token, revoke, introspect)
  keys/             keyset loading, rotation schedule, JWKS
  session/          login and consent challenges, user session
  identity/         users, clients, roles
  rbac/             permission evaluation
  proxy/            reverse proxy and identity propagation
  audit/            event schema and emission (RI-03)
  store/
    postgres/       source of truth
    redis/          rate limits, ephemeral state, denylist
pkg/
  tokenvalidator/   JWT/JWKS validation (see §7.4)
docs/
  THREAT-MODEL.md   threats, mitigations, residuals
  ARCHITECTURE.md   packages and signatures (phase 0 deliverable)
  adr/              architectural decisions
```

**Signatures, no bodies, are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).**
`internal/config` was added to this tree while writing that document — it had
a commit scope and an issue (#12) already, but no package, which is exactly
the kind of gap writing signatures before code is supposed to surface.
`internal/oidc` was removed from it the other way round: planned, never
filled, and deleted empty by ADR-0001's amendment (#122) — OIDC's handlers
live in `cmd/usher`, its token claims in `internal/oauth`. `internal/oauth/grant`
went the same way (#131): `/token` dispatches its three grants with a `switch`
in `cmd/usher/token.go`, and the `Strategy` interface planned here never had an
implementation.

### 7.1 Storage split

| Data | Where | Why |
|---|---|---|
| Clients | Versioned configuration, loaded at startup | RF-01; no runtime registration |
| Users, roles | Postgres | Durable source of truth |
| Refresh token families | **Postgres** | Data loss means reuse detection fails silently ([ADR-0002](docs/adr/0002-postgres-holds-refresh-families.md)) |
| Granted consent | Postgres | Auditable, revocable (RF-13) |
| Authorization codes and their tombstones | Redis | TTL ≤ 60s; tombstone per RS-04 |
| Login/consent challenges | Redis | Ephemeral |
| Browser sessions | Redis | Loss forces a new login, which fails safe (RS-31) |
| Rate limit buckets | Redis | Shared across instances (see RNF-07) |
| Access token denylist | Redis | TTL equals token TTL; gateway-only (RF-06) |
| Private keys | Mounted keyset, never the database or the repository | [ADR-0015](docs/adr/0015-signing-keyset-custody-and-rotation.md) |
| Audit events | Structured log stream, shipped to `crier` | RI-03, [ADR-0017](docs/adr/0017-audit-events-ship-to-crier.md); the reuse-detected fact is also on the family row |

What Redis loses is, row by row, either safe to lose or a stated residual: a lost
code or challenge fails the flow; a lost session forces a login; a lost
tombstone is RS-04's residual; a lost denylist entry un-revokes an access token
for at most its remaining TTL. That last one is why the denylist is in Redis and
not somewhere weaker, and why RF-12 caps the TTL.

### 7.2 Middleware pipeline

Order, in every chain:
`secureheaders` → `ratelimit` → `validate.MaxBodyBytes` → `[csrf]` → `[auth]` →
`[rbac]` → handler.

Headers outermost so that 401, 403 and 429 carry them too. The body limit
precedes CSRF because CSRF parses form-encoded bodies.

| Route group | csrf | auth | rbac | Rate limit | `no-store` |
|---|---|---|---|---|---|
| `/.well-known/*`, JWKS | no | no | no | permissive, cached | no |
| `/authorize` | no | session | no | moderate | no |
| `/login`, `/consent` (POST) | **yes** | — | no | **strict**, two axes | yes |
| `/token`, `/revoke`, `/introspect` | **no** | client auth | no | **strict**, weighted `AllowN` | yes |
| `/userinfo` | no | bearer, userinfo audience (RS-08) | no | per token | yes |
| `/api/**` | no | bearer | yes | per token/account | upstream's choice |

**On `preset.API`:** it is now a defensible option. It requires the proxy
topology to be declared (`TrustedProxies` or `DirectlyExposed`) instead of
silently giving every client one shared bucket, and `DisableCSRF: true` is
explicit and greppable. Explicit composition remains the MVP choice because the
`/authorize` and `/api/**` chains are not modelled by the preset. Recorded as
[ADR-0006](docs/adr/0006-explicit-middleware-composition.md) — a choice between
two valid options, not a rejection.

### 7.3 Responsibility boundary with `moat`

| Requirement | `moat` provides | The gateway still does |
|---|---|---|
| RS-02 | `validate.URL` (scheme, rejects `//host`) | Exact match against registered `redirect_uris` |
| RS-12a | `csrf`: signed double-submit, Origin/Referer, `__Host-` | Apply only on browser routes |
| RS-12b | `csrf.Rotate` — the CSRF half of fixation | Rotate the **session id** |
| RS-15, RS-23 | `secret.Value` | Use it for every secret, not just the obvious ones |
| RS-17 | — | Entirely the gateway's |
| RS-21 | — | Entirely the gateway's (`http.Server` config, not middleware) |
| RS-22 | `realip` + `Limiter.Allow`/`AllowN` | Choose keys and weights; keep the account axis from becoming an oracle (RS-14, RS-35) |
| RS-26 | `secureheaders.NoStore` | Apply on the right routes |
| RS-27 | `secureheaders.ClearSiteData` | Real server-side invalidation (RS-31) |
| RS-32 | `secureheaders` CSP | Confirm `frame-ancestors 'none'` on every HTML response |
| RNF-07 | `Store.EvictionCheck()` | Assert `Verified()` at startup and fail |
| RS-36 | Per-request CSP nonce + `Nonce(r)` | Use it in login/consent templates; handle `WithNonceErrorHandler` |

**`realip` topology, both sides.** The gateway is the trusted proxy for the
resource server and may itself sit behind a load balancer. Two separate
configurations, and getting either wrong silently disables rate limiting: the
gateway declares the CIDRs of the balancer in front of it (or declares direct
exposure); the resource server declares the gateway's CIDR. An empty trust set is
a construction error, and so is `0.0.0.0/0` — the latter matters most here,
because it is the easy way out for someone who does not know the balancer's
range. Recorded as [ADR-0010](docs/adr/0010-realip-topology-both-sides.md).

**Trust decision.** `moat` is a first-party, pre-1.0, independently unaudited
dependency. It is pinned to an exact version and never auto-upgraded: its
`ratelimit.Store` interface took a breaking rename in a minor release, and a
published satellite tag once did not compile. Upgrades are manual, with a build
verified from a clean directory. Recorded as
[ADR-0011](docs/adr/0011-moat-trust-decision.md) — the reasoning matters more
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
`tokenvalidator`'s public signature changes at the end of every phase**
([ADR-0009](docs/adr/0009-record-tokenvalidator-signature-changes.md)). That
count is the evidence the criterion asks for; without the record, the future
re-evaluation depends on memory. The demo resource server (RI-05) is its second
consumer inside this repository, which is what makes the count mean something.

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

These are expectations, not a mandate: a pattern the phase does not need is not
introduced for this table's sake. Field validation lives in the service layer,
not in handlers or middleware.

---

## 9. Technology

| Need | Choice | Considered |
|---|---|---|
| HTTP | `net/http` + `chi` | Works with `moat` without an adapter |
| Edge security | `moat` + `moat/redisstore` | — |
| Outbound resilience | `bastion` | Hand-rolled breaker — see [ADR-0016](docs/adr/0016-bastion-guards-the-proxy-path.md) |
| JOSE / JWKS | `lestrrat-go/jwx/v4` | `golang-jwt/jwt/v5` — leaner, weaker JWK support |
| Password hashing | `golang.org/x/crypto/argon2` | `bcrypt` |
| Postgres | `pgx/v5` | — |
| Redis | `go-redis/v9` | Already a `redisstore` dependency |
| Migrations | Embedded SQL, forward-only, advisory lock ([ADR-0018](docs/adr/0018-embedded-forward-only-migrations.md)) | `golang-migrate` — large tree, and down migrations this project would forbid |
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
  both implementations creates confidence without a guarantee. The control is
  noted in a comment above the test.
- **Integration** (`-tags=integration`): real Postgres and Redis via
  testcontainers, full flow end to end. In CI, an unavailable container fails the
  job rather than skipping it.
- **Fuzzing** of protocol parameter and JWT parsing. Property: no malformed input
  ever produces an accepted token.
- **Timing**: statistical comparison of login latency for existing versus
  non-existent users. Non-deterministic; a regression signal, not a CI gate.
- **Concurrency**: `-race` always, plus tests where simultaneous refresh
  exchanges (RS-11) and simultaneous code exchanges (RS-04) each yield exactly
  one issuance.
- **Properties, not instances.** Where a requirement applies to a *class* of
  points — every credential route carries `no-store`, every rejection carries the
  security headers, every HTML response forbids framing — the test enumerates
  those points from code, not from a hand-written list. A hand-written list goes
  stale at the next point added, and that is how a closed class reopens.
- **Threat probes.** Each `T-nn` in the threat model becomes a probe in a
  re-runnable script against the compose stack, and its output is committed.
- **External verification** (RI-06): `warden` and `sapper` against the compose
  stack, results recorded.
- **README examples run in CI.** The first snippet a visitor copies must compile.

---

## 11. Phases

| Phase | Delivery |
|---|---|
| 0 | This document, threat model, ADRs, CI guards, `docs/ARCHITECTURE.md` with signatures, schema, package skeleton |
| 1 | Identity: users, hashing under a concurrency bound, constant-work login, browser session, dual rotation |
| 2 | Authorization code + PKCE, `/authorize`, `/token` issuing **access tokens only**, login/consent challenge, consent record. Signed with a single key from the keyset — no rotation yet |
| 3 | Keys: rotation schedule, JWKS publication windows, background-refresh cache in `tokenvalidator` |
| 4 | Refresh tokens: issuance, rotation, reuse detection, revocation, `/revoke` |
| 5 | RBAC and scope intersection |
| 6 | Gateway: reverse proxy, header stripping, `bastion` on the outbound path, demo RS re-validation |
| 7 | Full OIDC: `id_token`, `nonce`, `prompt`/`max_age`, `/userinfo`, discovery, logout |
| 8 | `client_credentials`, `/introspect`, hardening |
| 9 | Verification: threat probes complete, `warden` and `sapper` runs recorded, release `v0.1.0` |
| — | Extensions: MFA (TOTP), sender-constrained tokens (DPoP/mTLS), back-channel logout, PAR, `task-api` as a second resource server |

v0.3 issued signed JWTs in phase 2 and introduced keys in phase 3. Phase 2 now
signs with one static key from the keyset; phase 3 adds only what rotation needs.

---

## 12. Decisions

The ADRs are in [`docs/adr/`](docs/adr/README.md), indexed there with their
status, reopening criteria and the questions still open. They are written before
the code they govern and amended, never rewritten.

---

## 13. MVP acceptance

The MVP is complete when a registered client completes the full flow —
`/authorize` → login → consent → code → `/token` → authenticated call through the
gateway → refresh → revocation — and:

- every negative test in §10 fails as expected, with each `RS-` covered by at
  least one test validated by a negative control;
- every `T-nn` in the threat model has a probe, and the probe output is
  committed;
- the `warden` and `sapper` runs of RI-06 are recorded, including the checks
  that did not apply and why.

---

## 14. Integration requirements

**RI-01 — `moat` for edge security, pinned exactly.** The properties consumed are
§7.3's table. The version is pinned and excluded from automated upgrades
([ADR-0011](docs/adr/0011-moat-trust-decision.md)).

**RI-02 — `bastion` guards every outbound proxy call** — one named breaker per
upstream ([ADR-0016](docs/adr/0016-bastion-guards-the-proxy-path.md)). This
project is bound by the two host-side rules `bastion/ADR-0009` fixed before this
code existed, and closes `bastion` issue #32:

1. `ErrOpenState` and `ErrTooManyRequests` map to `503` with `Retry-After`,
   never `500`.
2. The rate limiter runs once, on the way in. A call `bastion` refuses never
   re-charges the client's budget.

**RI-03 — Audit events are shipped to `crier`.** RF-09's events are emitted as
structured records with a versioned schema and exported to `crier`'s ingestion
endpoint, authenticated with the gateway's own credential (`crier/IR3`). They
carry no secret (RS-23). Durability and queryability are `crier`'s backend's;
what that costs is [ADR-0017](docs/adr/0017-audit-events-ship-to-crier.md).
When `crier` is unreachable, events queue in a bounded buffer and are then
dropped and counted; `/readyz` does not depend on `crier`.

**RI-04 — The identity header contract.** The gateway injects `X-Auth-Subject`,
`X-Auth-Client` and `X-Auth-Scope`, after stripping the namespace (RS-17). A
consumer may rely on them only when it restricts the peer allowed to set them to
the gateway's addresses — as `crier/IR7` does through `realip`. A consumer that
can be reached without passing through the gateway must not trust them, and the
resource server in this repository does not use them for authorization (RS-18).

**RI-05 — The demo resource server is part of this repository.**
`cmd/resource-server` validates tokens with `pkg/tokenvalidator` and is the
resource server of RNF-06 and §13
([ADR-0013](docs/adr/0013-demo-resource-server-in-repository.md)). `task-api`
authenticates with opaque server-side sessions by a decision recorded in its own
repository; this project does not reopen that decision. `task-api` as a second
resource server is an extension (§11), gated by an ADR in `task-api` first.

**RI-06 — `warden` and `sapper` verify the running stack.**
- `warden` (formerly `security-scanner`): its `jwt`, `redirect`, `authrequired`,
  `cache`, `headers`, `cors` and `xss` checks map onto RS-06, RS-02/RS-28,
  RS-26, RS-32 and the login templates. Unlike `crier` — where its confirmers
  had nothing to confirm against a JSON endpoint — `usher` renders HTML and talks
  to a database, so a clean report here means something.
- `sapper`: `ramp-up` to 429 verifies RF-07/RS-22 under concurrency, and fault
  injection verifies RI-02 and RNF-04. Both are on `sapper`'s roadmap and not in
  its v1; until they ship, the corresponding probes live in this repository's
  threat-probe script and say so.

A check that cannot apply is recorded as such, with the reason — a passing check
that verifies nothing is worse than an absent one.

---

## 15. Changes from v0.3

Recorded so the review can be audited rather than re-derived.

| Change | Why |
|---|---|
| Added RS-28 and reworded RS-01 | v0.3 had no rule against redirecting errors to an unverified `redirect_uri`, and RS-01's "before any other processing" made that rule impossible to follow |
| RS-04 requires atomic consumption and a tombstone | Only refresh consumption was atomic; a concurrent code exchange was the same race. Replay revocation needed a record that outlives the code |
| Added RS-29 (`iss`), RS-30 (`nonce`), RF-11 | RFC 9700 mix-up mitigation and the OIDC parameters were absent |
| Added RF-10, RS-31 and the sessions row in §7.1 | `/authorize` relied on a session nobody had specified — no cookie attributes, lifetime or store |
| Added RS-32 | Consent could be framed |
| Added RS-36 | Found by the threat model (T-21): template injection had a row in §7.3 but no id, so nothing could cite or test it |
| Added RS-33 | Argon2id on an unauthenticated endpoint is a memory-exhaustion lever |
| Added RS-34, RS-35 | Refresh was not bound to its client or grant; the account axis could be bypassed by case |
| RF-06 states the denylist is gateway-only; ADR-0014 | Revocation was described as complete when it is partial at the RS |
| Added RF-12 (lifetimes with bounds) | RS-09's formula needed a maximum access-token TTL nobody had set |
| RS-08 covers `/userinfo` | `/userinfo` had no audience, contradicting RS-08/RS-19 |
| Added the `RI-` section | `bastion/ADR-0009` and `crier/IR3`/`IR7` already bound this project, and nothing here said so |
| Phase 2 signs with a static key | v0.3 issued JWTs one phase before keys existed |
| Added RNF-08 to RNF-11 | CI-before-code, dependency allow-list, health/readiness, shutdown |
| ADR ids are four digits; §12 points at the index | `ADR-01` and `0011-…` were both in use |
| Project named `usher` throughout | The draft README had drifted to "gateway" |

---

## 16. Changes from v0.4

The M0 decisions, taken before the code they govern.

| Change | Why |
|---|---|
| RS-09 names RS256 as the default and the `kid` denylist as the emergency path | ADR-0015 accepted (#3) |
| RS-11 records the revocation reason on the family row | ADR-0017 accepted (#2): the reuse-detected fact must not depend on best-effort delivery |
| RI-03 states the behaviour when `crier` is unreachable | ADR-0017 accepted (#2) |
| §9 migrations: embedded SQL instead of `golang-migrate` | ADR-0018 (#4); one dependency fewer (RNF-02) |

---

## 17. Changes from v0.5

| Change | Why |
|---|---|
| Added `internal/config` to §7's package tree | Writing `docs/ARCHITECTURE.md` (#5) found a package the commit scopes and issue #12 already assumed but the tree never listed |
| §7 links `docs/ARCHITECTURE.md` | The signatures the foundation method's step 3 asks for now exist |
