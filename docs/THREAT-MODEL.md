# usher — Threat Model

**Version:** 0.1, written with requirements v0.4, before any code.
**Scope:** the authorization server, the gateway, the demo resource server, and
the stores they share.
**Companion to:** [`REQUIREMENTS.md`](../REQUIREMENTS.md). Every mitigation below
names the requirement that discharges it, and every security requirement appears
at least once in §5.

> A threat model that lists only the threats it defeats is marketing. The
> residual on each threat, and §7, are what make this one honest.

---

## 1. What is being protected

| Asset | Why it matters | Exposure |
| --- | --- | --- |
| **Signing keys** | Whoever holds one mints any token for any user, client and audience | Mounted keyset read by every instance (ADR-0015) |
| Refresh token families | Long-lived access on a user's behalf | Client storage; Postgres as SHA-256 (RS-10) |
| Access tokens | Bearer credentials to every resource server behind the gateway | In flight; client memory; upstream logs |
| Authorization codes | Exchangeable for tokens for 60 s | Browser URL, history, `Referer` |
| Password hashes | Offline cracking yields credentials reused elsewhere | Postgres |
| Client secrets | Impersonation of a confidential client | Configuration, as SHA-256 (RS-16) |
| Browser sessions | Skip login for the session's lifetime | Cookie; Redis as SHA-256 (RS-31) |
| Audit trail | Detecting — and proving — that any of the above happened | `crier` (RI-03) |
| Availability of `/token` and the gateway | Every resource server behind it goes down with it | Public |

**The asymmetry.** Every other asset's compromise is bounded by a lifetime
(RF-12) or revocable (RF-06, RS-11). A signing key's is bounded by nothing
except removing it from the JWKS and waiting out every consumer's cache: until
then every token it signs is indistinguishable from a real one. That is why keys
live outside the database (§7.1 of the requirements), why rotation is a
first-class phase, and why T-18 has the longest residual here.

## 2. Actors and capabilities

| Actor | Assumed capability | Assumed *not* to have |
| --- | --- | --- |
| Internet attacker | Any request to any public endpoint, at volume, from many IPs; can register nothing | The signing keys; the ability to break TLS |
| Malicious or compromised client | Its own valid `client_id` and secret; can send users through the flow | Another client's secret; a way to add a `redirect_uri` at runtime (RF-01) |
| Network observer between user and AS | Sees what TLS does not hide: timing, sizes, destination | Plaintext |
| Holder of a leaked artifact | Anything that ended up in a log, history, `Referer` or a DB dump | A live session unless one leaked |
| Attacker on the internal network | Can reach a resource server without going through the gateway | The gateway's addresses as a source (RI-04) |
| Operator | Configuration, keyset, infrastructure | — trusted; misconfiguration is in scope where it is detectable (RNF-05) |
| **Victims who are not users** | A client following a redirect; `crier` ingesting what the gateway sends | — threats reaching them through this system are still this system's |

## 3. Trust boundaries

```
 Internet  ║  usher (AS + gateway)  ║  internal network            ║  operator
           ║                        ║                              ║
 browser ──╫──▶ /authorize /login   ║                              ║  keyset (mounted)
 client  ──╫──▶ /token /revoke      ║──▶ Postgres, Redis           ║  client config
 client  ──╫──▶ /api/** ────────────╫──▶ resource server           ║
           ║                        ║──▶ crier (audit)             ║
```

- **Internet → usher.** Everything is untrusted: every header, including
  `X-Forwarded-For` beyond the declared proxies (ADR-0010) and every `X-Auth-*`
  (RS-17). usher may assume only what it validated in this request.
- **usher → internal network.** *Not* a trust boundary in the inbound direction:
  the resource server re-validates the token (RS-18) as though the network were
  hostile, because someone on it can reach the resource server directly.
- **usher → Redis.** Trusted for integrity, not for retention: anything in Redis
  may vanish, and §7.1 of the requirements states what each loss costs.
- **Operator → usher.** Trusted, but checked where checking is cheap: lifetimes
  above their bounds, an empty `realip` trust set, an unverified eviction policy
  and unknown audiences all refuse to start (RNF-05).

## 4. Threats

### T-01 — Authorization code interception and replay
**Actor:** holder of a leaked artifact; malicious app on the device.
**Impact:** tokens for the victim's account.
**Mitigation:** RS-01 (PKCE, S256 only), RS-04 (single use, atomic, 60 s, bound
to client and redirect, replay revokes), RS-05, RS-24.
**Residual:** a replay after the tombstone expires or after Redis loses it is an
ordinary `invalid_grant` and revokes nothing. The code stays unusable; only the
*detection* is bounded.

### T-02 — Open redirect through `redirect_uri`
**Actor:** internet attacker crafting an `/authorize` link.
**Impact:** code or error delivered to the attacker; the AS's domain lends a
phishing link its credibility.
**Mitigation:** RF-01 (registration validated), RS-02 (exact match), RS-28 (no
redirect before the target is verified).
**Residual:** a registered `redirect_uri` whose own host has an open redirect is
the client's defect. usher cannot see it.

### T-03 — CSRF on the OAuth redirect (login CSRF)
**Actor:** internet attacker.
**Impact:** the victim's client session is bound to the attacker's account.
**Mitigation:** RS-03.
**Residual:** `state` protects only a client that checks it. usher returns it
unchanged; it cannot enforce the check.

### T-04 — Mix-up between authorization servers
**Actor:** a malicious AS the same client also talks to.
**Impact:** the client sends a code from usher to the attacker's token endpoint.
**Mitigation:** RS-29 (`iss` in every authorization response).
**Residual:** same shape as T-03 — the client must compare `iss`.

### T-05 — Token forgery: `alg: none` and key confusion
**Actor:** internet attacker.
**Impact:** arbitrary identity at every resource server.
**Mitigation:** RS-06 (allow-list fixed at construction), RS-07 (full claim set).
**Residual:** none known, conditional on the allow-list being built from
configuration and never from the token.

### T-06 — Wrong token in the wrong place
**Actor:** malicious client; holder of a leaked ID token.
**Impact:** an ID token — often logged, sent to front-ends — used as an API
credential; a token for resource server A replayed at B; an ID token replayed
into a client.
**Mitigation:** RS-08 (`aud` and `typ`, `/userinfo` included), RS-19 (audience per
route), RS-30 (`nonce`).
**Residual:** a resource server outside this repository that skips `aud` is
beyond usher's reach.

### T-07 — Stolen refresh token
**Actor:** holder of a leaked artifact.
**Impact:** long-lived access on the user's behalf.
**Mitigation:** RS-10 (stored hashed), RS-11 (reuse revokes the family, atomically),
RS-34 (bound to client and grant), RF-04 and ADR-0012 (no grace window), RF-12
(idle and absolute lifetimes).
**Residual:** reuse detection needs the legitimate client to come back. If the
attacker refreshes first and the victim never refreshes again, the attacker holds
the family until the idle or absolute lifetime ends. The strict rotation also
logs out a legitimate client whose retry races its own request — a cost
ADR-0012 accepts.

### T-08 — Stolen access token
**Actor:** holder of a leaked artifact.
**Impact:** API access until expiry.
**Mitigation:** RF-12 (≤ 15 min), RF-06 (gateway denylist), RS-24, RS-26.
**Residual:** these are bearer tokens with no sender constraint; whoever holds one
is the user (DPoP is an extension). A resource server reached directly never
consults the denylist, so there the TTL is the only bound (ADR-0014).

### T-09 — Credential stuffing and password guessing
**Actor:** internet attacker with a breach corpus and a botnet.
**Impact:** account takeover.
**Mitigation:** RS-13, RS-22 (IP and account axes), RS-35 (one canonical
identifier, so the account axis cannot be split).
**Residual:** a slow, distributed attack under both thresholds succeeds against a
weak password. Without MFA that is the ceiling of this design (§1.1).

### T-10 — User enumeration
**Actor:** internet attacker.
**Impact:** a list of valid accounts for T-09 and phishing.
**Mitigation:** RS-14 (timing, message, rate-limit axis), RS-33 (the saturation
path does equal work), RS-25.
**Residual:** timing equality is a statistical property measured outside CI
(§10). There is no registration or password-reset endpoint in the MVP; each would
be a new enumeration surface when added.

### T-11 — Session fixation and hijacking at the AS
**Actor:** internet attacker; network observer.
**Impact:** the attacker rides the victim's SSO session through `/authorize`.
**Mitigation:** RS-12b (session id and CSRF token rotated on login), RS-31
(cookie attributes, hashed storage, server-side lifetimes and logout), RS-27.
**Residual:** an XSS on the AS origin (T-21) can act within the session without
reading the cookie.

### T-12 — Forged form submissions and clickjacking
**Actor:** internet attacker hosting a page the victim visits.
**Impact:** a login or a consent grant the user did not intend.
**Mitigation:** RS-12a (CSRF on `/login` and `/consent`), RS-32 (no framing).
**Residual:** none known for these two routes.

### T-13 — Identity header spoofing
**Actor:** internet attacker; attacker on the internal network.
**Impact:** any identity at a resource server that trusts the headers.
**Mitigation:** RS-17 (allow-list strip before inject), RS-18 (the RS decides from
the token), RI-04 (consumers must pin the peer).
**Residual:** a consumer that trusts `X-Auth-*` from any peer is outside usher's
control. RI-04 states the contract; it cannot enforce it.

### T-14 — Credential leakage at rest and in transit through side channels
**Actor:** holder of a leaked artifact — a log reader, a proxy cache, a DB dump.
**Impact:** usable tokens, codes or secrets.
**Mitigation:** RS-10, RS-15, RS-16, RS-23 (no secrets in logs, errors, audit
events or spans), RS-24 (no tokens in URLs), RS-25, RS-26 (`no-store`).
**Residual:** process memory — the guarantee is against accidental printing, not
an in-process attacker (RS-23).

### T-15 — Denial of service against the AS
**Actor:** internet attacker.
**Impact:** no logins, no refresh, and so no access to anything behind the gateway.
**Mitigation:** RF-07 and RS-22 (rate limits), RS-09 (rate-limited JWKS refetch on
unknown `kid`), RS-21 (timeouts), RS-33 (bounded hashing memory).
**Residual:** volumetric L3/L4 floods are the infrastructure's (§7). RS-33's
bound turns memory exhaustion into `503`s: availability still degrades, but the
process survives.

### T-16 — Rate-limit bypass
**Actor:** internet attacker.
**Impact:** T-09 and T-15 at full speed.
**Mitigation:** RS-22 with `realip` (ADR-0010: the key derives from the first
untrusted peer), RNF-07 (`noeviction`, asserted), RNF-04 (Redis failure denies),
RNF-05.
**Residual:** the eviction check is a snapshot taken at startup and, in cluster
mode, sees only the masters reachable then (RNF-07).

### T-17 — Upstream failure cascading into the gateway, or leaking through it
**Actor:** none needed — an unhealthy resource server — or an attacker probing
error paths.
**Impact:** gateway goroutines pile up behind a dead upstream; stack traces or
internal hostnames reach the client.
**Mitigation:** RS-20 (custom `ErrorHandler`, hop-by-hop stripped), RS-21
(upstream timeout and size limit), RI-02 (`bastion` breaker, `503` +
`Retry-After`).
**Residual:** a slow-but-not-failing upstream below the breaker's threshold still
holds connections up to the upstream timeout.

### T-18 — Signing key compromise
**Actor:** anyone who reads the mounted keyset.
**Impact:** unlimited forgery — see the asymmetry in §1.
**Mitigation:** keys never in the database or the repository (§7.1), custody and
rotation per ADR-0015, RS-09 (publication windows), RS-06 (only listed keys
verify).
**Residual:** the largest here. There is no emergency path shorter than removing
the key from the JWKS and waiting out `consumer_JWKS_cache_TTL`; tokens already
issued under it stay valid at any consumer that cached it. ADR-0015 is proposed,
not accepted, and this residual is one of its open questions.

### T-19 — Loss or forgery of the audit trail
**Actor:** an attacker covering tracks; anyone able to reach `crier`.
**Impact:** an incident nobody can reconstruct — reuse detection that fired and
was never seen.
**Mitigation:** RF-09 (versioned schema), RI-03 (authenticated shipping;
`crier` overwrites client-asserted identity, `crier/ADR-0008`), RS-23.
**Residual:** delivery depends on `crier`; its drops are counted, not prevented.
Whether a best-effort sink is acceptable for security events is exactly what
ADR-0017 leaves open.

### T-20 — Scope escalation and consent abuse
**Actor:** malicious client.
**Impact:** more access than the user granted or the role allows.
**Mitigation:** RF-05 (client scope ∩ role), RF-13 (consent per scope set, re-prompt
on growth), RS-34 (refresh cannot widen).
**Residual:** a user who clicks "allow" on an honest-looking consent screen has
consented. The consent page's wording is the only defence, and it is not a
requirement.

### T-21 — Script injection in the login and consent pages
**Actor:** malicious client (through its registered name or requested scopes);
internet attacker (through reflected parameters).
**Impact:** script on the AS origin — credential theft at the login form, consent
granted by script.
**Mitigation:** RS-36 (`html/template` only, per-request CSP nonce), RS-32.
**Residual:** none known, conditional on no template ever using a type that
disables escaping (`template.HTML` and friends) on a value that did not originate
in the binary.

## 5. Coverage matrix

| Threat | Requirements |
| --- | --- |
| T-01 | RS-01, RS-04, RS-05, RS-24 |
| T-02 | RF-01, RS-02, RS-28 |
| T-03 | RS-03 |
| T-04 | RS-29 |
| T-05 | RS-06, RS-07 |
| T-06 | RS-08, RS-19, RS-30 |
| T-07 | RF-04, RF-12, RS-10, RS-11, RS-34 |
| T-08 | RF-06, RF-12, RS-24, RS-26 |
| T-09 | RS-13, RS-22, RS-35 |
| T-10 | RS-14, RS-25, RS-33 |
| T-11 | RS-12b, RS-27, RS-31 |
| T-12 | RS-12a, RS-32 |
| T-13 | RS-17, RS-18, RI-04 |
| T-14 | RS-10, RS-15, RS-16, RS-23, RS-24, RS-25, RS-26 |
| T-15 | RF-07, RS-09, RS-21, RS-22, RS-33 |
| T-16 | RS-22, RNF-04, RNF-05, RNF-07 |
| T-17 | RS-20, RS-21, RI-02 |
| T-18 | RS-06, RS-09 |
| T-19 | RF-09, RS-23, RI-03 |
| T-20 | RF-05, RF-13, RS-34 |
| T-21 | RS-32, RS-36 |

**Reverse direction.** Every `RS-` from RS-01 to RS-36 appears above. Functional
and non-functional requirements appear where they mitigate something; the rest
(RF-02, RF-03, RF-08, RF-10, RF-11, RNF-01 to RNF-03, RNF-06, RNF-08 to RNF-11)
are function or process, not mitigations, and are not claimed as hardening.

## 6. Verification

- Each `RS-` gets a test validated by a negative control (requirements §10).
- Each `T-nn` becomes a probe in a re-runnable script run against the compose
  stack; the output is committed. A threat that cannot be probed from outside —
  T-18, T-19 — gets a line in the script saying so and why, rather than silence.
- `warden` and `sapper` cover the subset of these they were built for (RI-06).
  Their reports are committed next to the probe output, including the checks that
  did not apply.

## 7. Explicitly not addressed

Listed so nobody infers coverage from silence.

| Not addressed | Whose it is instead |
| --- | --- |
| TLS termination and certificate management | The operator's load balancer or ingress |
| Volumetric L3/L4 floods | Network infrastructure |
| An attacker who can read process memory or the host filesystem | The host's isolation; see T-18 |
| Phishing of the user's password | MFA, an extension (§11 of the requirements) |
| A malicious operator | Out of scope by definition |
| Supply-chain compromise of a dependency beyond what pinning and review catch | RNF-09 narrows the surface; it does not close it |
| Malware or extensions in the user's browser | The user's device |
