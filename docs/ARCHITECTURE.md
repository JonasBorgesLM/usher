# usher — Architecture

**Companion to:** [`REQUIREMENTS.md`](../REQUIREMENTS.md) §7 (package tree, storage
split, middleware pipeline) and [`docs/adr/`](adr/README.md).

This document writes the requirements as **signatures with no bodies** — the
foundation method's step 3. A signature is checkable in a way prose is not: it
either satisfies `check-boundaries.sh`'s rules or it does not, and it either
compiles against another package's exported names or it does not. Where the
**order** two calls happen in is itself a requirement, the flow sections below
say so explicitly, because code with the steps reversed compiles identically.

Nothing here is final. A signature changes when implementation finds it wrong;
what must not change silently is the requirement or ADR it satisfies — if a
signature stops satisfying one, the requirement or the signature is wrong, and
which one is a decision, not a typo.

---

## 1. Package map

The tree in REQUIREMENTS §7, plus one package that document surfaces as
missing: configuration loading (RNF-03, RNF-05) has commit scope `config` and
issue #12 already, but no package. Adding it here is the kind of gap writing
signatures is supposed to surface before it is expensive.

```
cmd/
  usher/            the AS + gateway binary — wires everything below
  resource-server/  demo RS (RI-05); imports pkg/ only, never internal/
internal/
  config/           NEW. Env + versioned files → Config; fails closed (RNF-05)
  oauth/            protocol only: codes, families, consent, TokenResponse
    grant/          one Strategy per grant_type
  oidc/             discovery, id_token, userinfo
  keys/             keyset loading, signing, JWKS, the kid denylist
  session/          login/consent challenges, browser sessions
  identity/         users (people) and clients (registered apps)
  rbac/             permission evaluation
  proxy/            reverse proxy, identity headers, the gateway denylist
  audit/            event schema and emission (RI-03)
  store/
    postgres/       satisfies identity.UserStore, oauth.FamilyStore, oauth.ConsentStore
    redis/          satisfies oauth.CodeStore, session.ChallengeStore,
                    session.SessionStore, proxy.Denylist
pkg/
  tokenvalidator/   JWT/JWKS validation — extractable; imports nothing internal
```

**Boundary rule (ADR-0001), restated as what the signatures below must not do:**
nothing in `internal/oauth` or `internal/oidc` may reference a type from
`internal/proxy`, and nothing in `internal/proxy` may reference a type from
`internal/oauth` or `internal/oidc`. §7 below marks, package by package, why
this holds by construction rather than by discipline: `internal/proxy` reaches
tokens only through `pkg/tokenvalidator` and `internal/keys`, never through
`internal/oauth`'s issuance types.

Interfaces are declared in the package that **consumes** them (Go convention);
the concrete Postgres or Redis type satisfying one lives under `internal/store/`
and is never imported by name outside `cmd/usher`'s wiring.

---

## 2. `internal/oauth` — protocol state

### 2.1 Authorization codes (RS-04, RS-05)

```go
package oauth

// Code is a pending authorization code, alive for at most RF-12's bound.
type Code struct {
	Value         string    // opaque, ≥128 bits from crypto/rand
	ClientID      string
	RedirectURI   string    // exact string this code was issued for (RS-02)
	CodeChallenge string    // S256 only (RS-01)
	Nonce         string    // "" if the request carried none (RS-30)
	Scope         []string
	Subject       string
	ExpiresAt     time.Time
}

// CodeStore persists pending codes and their post-consumption tombstones.
// Redis-backed (REQUIREMENTS §7.1).
type CodeStore interface {
	// Save rejects a colliding Value with ErrCodeExists rather than
	// overwriting it — a collision means the caller must draw a fresh value,
	// never reuse one.
	Save(ctx context.Context, c Code) error

	// Consume atomically deletes and returns c, or ErrCodeNotFound if it was
	// never issued, already consumed, or expired. One round trip (GETDEL or
	// a Lua script) — RS-04's negative control is a store that GETs then
	// DELs, which lets two concurrent callers both succeed.
	Consume(ctx context.Context, value string) (Code, error)

	// Tombstone records that value produced familyID, kept for ttl (the
	// access token's maximum lifetime, RF-12). Called after issuance
	// succeeds, so RS-04's replay-revokes-everything window opens as late
	// as possible.
	//
	// Residual, stated rather than hidden: a crash between a successful
	// Consume and this call leaves that one code's replay undetectable —
	// the same shape as the tombstone-expiry residual REQUIREMENTS RS-04
	// already names, just a second way into it.
	Tombstone(ctx context.Context, value, familyID string, ttl time.Duration) error

	// TombstonedFamily reports the family value produced, if its tombstone
	// is still live. Called when Consume fails, to tell "replay of a code
	// that succeeded once" (revoke) from "never existed or expired"
	// (ordinary invalid_grant).
	TombstonedFamily(ctx context.Context, value string) (familyID string, found bool, err error)
}
```

### 2.2 Refresh families (RS-10, RS-11, RS-34, ADR-0002, ADR-0012)

```go
// Family is one refresh-token lineage. RevokedReason is set by whichever of
// RF-06 (client or admin), RF-13 (consent revoked) or RS-11 (reuse) revoked
// it — ADR-0017 records the reason on this row precisely so that fact
// survives independent of the audit stream reaching crier.
type Family struct {
	ID            string
	ClientID      string    // RS-34: rotation requires the same client
	Subject       string
	Scope         []string  // RS-34: a later request may only narrow this
	CreatedAt     time.Time
	ExpiresAt     time.Time // absolute lifetime (RF-12)
	RevokedAt     *time.Time
	RevokedReason string    // "", "reuse_detected", "revoked_by_client", "admin", "consent_revoked"
}

// RefreshToken is one issued token in a family. The raw value is never
// stored (RS-10) — only its hash.
type RefreshToken struct {
	FamilyID   string
	Hash       [32]byte // SHA-256 of the opaque token
	IssuedAt   time.Time
	ExpiresAt  time.Time // idle lifetime (RF-12)
	ConsumedAt *time.Time
}

// FamilyStore is Postgres-backed (ADR-0002: losing it makes reuse detection
// fail silently, which is worse than not detecting it).
type FamilyStore interface {
	// CreateFamily returns the family's own generated id (#37: its first
	// real caller needs it immediately, to Tombstone the authorization
	// code that produced it, without a second round trip through Lookup
	// just to learn what CreateFamily already knew).
	CreateFamily(ctx context.Context, f Family, first RefreshToken) (familyID string, err error)

	// Rotate is RS-11's atomic compare-and-set. The race is decided entirely
	// by one conditional UPDATE (§2.2's schema note has the exact query) —
	// a SELECT followed by an UPDATE is what RS-11 forbids, because it lets
	// two concurrent callers each see "unconsumed" before either writes.
	// Only the caller whose UPDATE actually affects a row inserts next, in
	// the same database transaction as that UPDATE — same transaction,
	// not necessarily the same statement, since the transaction is what
	// makes "consumed but next was never inserted" impossible to observe,
	// while the UPDATE alone is what makes the race impossible to win twice.
	// consumed reports which of those two things the caller was.
	Rotate(ctx context.Context, hash [32]byte, next RefreshToken) (consumed bool, err error)

	// Revoke sets RevokedAt/RevokedReason idempotently.
	Revoke(ctx context.Context, familyID, reason string) error

	// RevokeAllForSubject is administrative revocation (RF-06): every
	// family subject holds, across every client, revoked with reason.
	RevokeAllForSubject(ctx context.Context, subject, reason string) error

	// RevokeForSubjectAndClient is consent revocation (RF-13): only the
	// families subject holds under clientID (#38: this used to be
	// described as a mode of RevokeAllForSubject -- its first real
	// caller needed its own method instead, the same "the first real
	// caller decides" reasoning #37 already applied to CreateFamily).
	RevokeForSubjectAndClient(ctx context.Context, subject, clientID, reason string) error

	// Lookup finds the family and token owning hash, for RS-34's binding
	// checks before Rotate is attempted.
	Lookup(ctx context.Context, hash [32]byte) (Family, RefreshToken, error)
}
```

**Schema (issue #6).** `internal/store/postgres/migrations/0001_initial_schema.sql`
holds `users`, `refresh_families`, `refresh_tokens` and `consent` — never a
`clients` table, since RF-01 makes those versioned configuration, not a
database row. `refresh_tokens.hash` is `BYTEA CHECK (octet_length(hash) = 32)`:
structurally the width of a SHA-256 digest and nothing else, so there is no
column shape a raw token could be written to by mistake (RS-10). `Rotate`'s
one conditional UPDATE, as implemented (#36):

```sql
UPDATE refresh_tokens t SET consumed_at = now()
FROM refresh_families f
WHERE t.hash = $1 AND t.consumed_at IS NULL AND f.id = t.family_id AND f.revoked_at IS NULL;
```

This is one condition wider than the query this section originally described
(`WHERE hash = $1 AND consumed_at IS NULL` alone, with no join). #36's own
negative control found why: a family revoked for reusing one token still let
that token's own never-consumed successor rotate normally afterward, since
the successor's row had its own `consumed_at IS NULL` and nothing else
checked the family at all. Folding `f.revoked_at IS NULL` into the same
statement closes that without opening a second read-then-write window next
to the one RS-11 already forbids.

`RowsAffected() == 1` is `consumed == true`; `== 0` is reuse (including a
revoked family, now). Verified against a real Postgres 16 under concurrency:
`TestRefreshTokenConsumption_AtomicUnderConcurrency`
(`internal/store/postgres/migrate_integration_test.go`) pins the bare
UPDATE's own atomicity ahead of `FamilyStore.Rotate`'s existence — fifty
goroutines racing it on one row, exactly one reports success, and the
SELECT-then-UPDATE negative control let 44 to 50 of 50 "win." #36's own
`TestRotateRefreshToken_ConcurrentReuse_ExactlyOneIssuanceFamilyRevoked`
(`internal/store/postgres/families_integration_test.go`) repeats this
through the real `Rotate` and the `RotateRefreshToken` orchestration
(`internal/oauth/rotate.go`), additionally asserting the family ends up
revoked and a high-severity audit event was emitted.

### 2.3 Consent (RF-13)

```go
// ConsentStore is Postgres-backed, auditable (REQUIREMENTS §7.1).
type ConsentStore interface {
	// Granted reports the scopes previously granted, or ok=false if none —
	// never an error for "no consent yet".
	Granted(ctx context.Context, subject, clientID string) (scope []string, ok bool, err error)

	// Grant replaces any prior grant for the pair with scope. A request for
	// a scope outside the prior grant re-prompts and then calls this with
	// the union (RF-13) — Grant itself does not union; the caller decides
	// what "the new grant" is.
	Grant(ctx context.Context, subject, clientID string, scope []string) error

	Revoke(ctx context.Context, subject, clientID string) error
}
```

### 2.4 Token issuance surface

```go
// TokenResponse is what POST /token serializes on success (RF-03).
type TokenResponse struct {
	AccessToken  string
	RefreshToken string // "" when this grant does not rotate one
	IDToken      string // "" unless the grant's scope included openid
	TokenType    string // always "Bearer"
	ExpiresIn    int
	Scope        string
}
```

---

## 3. `internal/oauth/grant` — one Strategy per grant type (§8)

```go
package grant

// Strategy is dispatched by the /token Facade (§8's Facade pattern) on the
// request's grant_type.
type Strategy interface {
	GrantType() string

	// Issue validates the request against this grant's own rules and
	// returns tokens, or an RFC 6749 §5.2 error (RS-25) — never one that
	// leaks internal detail. client is already authenticated by the Facade
	// before Issue is called; a Strategy does not re-authenticate it.
	Issue(ctx context.Context, r *http.Request, client identity.Client) (oauth.TokenResponse, error)
}
```

`AuthorizationCode` (M2) and `RefreshToken` (M4) are the two Strategies in the
MVP; `ClientCredentials` (M8) is the third. Each is a small, separately
testable type — the pattern exists so a grant's rules do not leak into the
Facade's dispatch code.

---

## 4. `internal/session` — challenges and the browser session

### 4.1 Login/consent challenge (RS-05)

```go
package session

// Challenge is one pending /authorize flow, addressed by an opaque id that
// carries no request parameters (RS-05).
type Challenge struct {
	ID            string
	ClientID      string
	RedirectURI   string
	Scope         []string
	State         string
	CodeChallenge string
	Nonce         string
	Subject       string // "" until login succeeds
	ExpiresAt     time.Time // RF-12
}

// ChallengeStore is Redis-backed (ephemeral, REQUIREMENTS §7.1).
type ChallengeStore interface {
	Save(ctx context.Context, c Challenge) error

	// Get reads without consuming — /login and /consent each render the
	// same challenge across a GET/POST pair before the flow completes.
	Get(ctx context.Context, id string) (Challenge, error)

	// SetSubject records the authenticated subject on a still-pending
	// challenge, between login succeeding and /consent.
	SetSubject(ctx context.Context, id, subject string) error

	// Consume atomically deletes and returns c — single-use (RS-05), same
	// shape as oauth.CodeStore.Consume. Called once, when /authorize is
	// ready to mint a Code.
	Consume(ctx context.Context, id string) (Challenge, error)
}
```

### 4.2 Browser session (RF-10, RS-31)

```go
// BrowserSession is the AS's own login session, independent of any OAuth
// client's session.
type BrowserSession struct {
	ID        string    // opaque, ≥256 bits; stored as its SHA-256 (RS-31)
	Subject   string
	AuthTime  time.Time // RF-11's auth_time, under max_age
	IdleUntil time.Time
	ExpiresAt time.Time // absolute lifetime (RF-12)
}

// SessionStore is Redis-backed.
type SessionStore interface {
	Save(ctx context.Context, s BrowserSession) error

	// Get looks up by the SHA-256 of rawID and extends IdleUntil (RF-12) —
	// or returns ErrSessionNotFound past either lifetime.
	Get(ctx context.Context, rawID string) (BrowserSession, error)

	// Delete ends the session server-side. Called before the response that
	// clears the cookie (RS-31: "before responding" is the requirement, not
	// a suggestion — a crash between clearing the cookie and this call
	// would otherwise leave a session alive with no client that can present it,
	// which is harmless, but the reverse order is not).
	Delete(ctx context.Context, rawID string) error
}
```

---

## 5. `internal/identity` — people and registered apps

```go
package identity

// User is a person who can authenticate (RS-13's hash, RF-05's role).
type User struct {
	ID           string
	Identifier   string // canonicalized (RS-35) — the form looked up and
	                     // rate-limited on; two spellings of one identifier
	                     // is two accounts, not one
	PasswordHash string // PHC string, params versioned (RS-13)
	Role         string
}

// UserStore is Postgres-backed.
type UserStore interface {
	// ByIdentifier looks up by the canonicalized form. ok=false — never an
	// error — when none exists, so RS-14's constant-work login proceeds
	// identically either way.
	ByIdentifier(ctx context.Context, identifier string) (u User, ok bool, err error)

	// UpdateHash rehashes on a successful login against weaker-than-current
	// parameters (RS-13). Never called on a failed attempt.
	UpdateHash(ctx context.Context, userID, newHash string) error
}

// Client is a registered OAuth client (RF-01). Loaded from versioned
// configuration, not a Postgres row — there is no ClientStore.
type Client struct {
	ID             string
	Confidential   bool
	SecretHash     string   // SHA-256; "" for a public client (RS-16)
	RedirectURIs   []string // exact strings (RS-02) — no pattern, no prefix
	GrantTypes     []string
	Scopes         []string
	Audiences      []string
	RequireConsent bool
}

// LoadClients parses and validates a client registry file. A relative
// redirect_uri, one with a fragment, or a scheme outside allowedSchemes is a
// load error (RF-01) — this is called from internal/config at startup, so
// that error becomes RNF-05's refusal to start, never a runtime surprise.
func LoadClients(path string, allowedSchemes []string) ([]Client, error)
```

---

## 6. `internal/keys` — signing keys and the JWKS

```go
package keys

// Key is one keyset entry: a private key plus the publication schedule
// RS-09 requires and ADR-0015 fixes the loader against.
type Key struct {
	KID       string
	Algorithm tokenvalidator.Algorithm // RS256 by default (ADR-0015 amendment)
	Private   crypto.Signer
	PublishAt time.Time
	SignFrom  time.Time
	RetireAt  time.Time
}

// Keyset is the loaded, validated set of keys.
type Keyset struct{ /* unexported */ }

// Load reads every key file under dir and validates its windows against
// clockSkew, maxAccessTokenTTL and consumerJWKSCacheTTL (RS-09's formula) —
// or returns the first violation, naming both keys and the window that
// failed. Called once at startup (ADR-0015: no periodic re-read; rotation
// is a restart that picks up a key already installed with a future
// SignFrom).
func Load(dir string, clockSkew, maxAccessTokenTTL, consumerJWKSCacheTTL time.Duration, deny Denylist) (*Keyset, error)

// Denylist is the emergency-revocation path (ADR-0015 amendment, T-18's
// residual): a listed kid is excluded from Signing and Published
// immediately, independent of its configured windows. Configuration, read
// once at Load — revoking a key takes a restart, and a consumer validating
// directly keeps accepting that key's tokens until its own JWKS cache
// expires, which is the residual and not a bug in this type.
type Denylist []string

// Signing returns the key that signs at t: the key whose SignFrom is the
// latest not after t among keys not yet RetireAt, or ErrNoSigningKey.
func (k *Keyset) Signing(t time.Time) (Key, error)

// Published returns every key visible in the JWKS at t — PublishAt ≤ t <
// RetireAt — with any denylisted kid already excluded.
func (k *Keyset) Published(t time.Time) []Key

// JWKS renders Published(t) as an RFC 7517 key set containing only public
// parameters (RS-09) — never a private one, asserted by a test on the
// marshalled JSON, not by review.
func (k *Keyset) JWKS(t time.Time) ([]byte, error)

// AsKeySource adapts a Keyset to tokenvalidator.KeySource for in-process
// validation — the gateway's own consumer of pkg/tokenvalidator
// (REQUIREMENTS §7.4), sharing the same Validator type the demo resource
// server drives over HTTP via NewJWKSSource.
func (k *Keyset) AsKeySource() tokenvalidator.KeySource
```

---

## 7. `pkg/tokenvalidator` — extractable, imports nothing internal

```go
package tokenvalidator

type Algorithm string

const (
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
)

// KeySource resolves a kid to a verification key. internal/keys.Keyset
// satisfies it for the gateway (in-process); NewJWKSSource satisfies it for
// the demo resource server and any external consumer (HTTP + JWKS).
type KeySource interface {
	Key(ctx context.Context, kid string) (crypto.PublicKey, Algorithm, error)
}

// Validator checks a JWT's signature against a fixed algorithm allow-list
// (RS-06) and a full claim set (RS-07). The allow-list is fixed here, at
// construction — a token's own alg header never selects how it is verified.
type Validator struct{ /* unexported */ }

// New fails with ErrNoAllowedAlgorithms if allowed is empty: a validator
// with an empty allow-list that silently rejects everything is a
// construction error, not a strict default.
func New(source KeySource, allowed []Algorithm, opts ...Option) (*Validator, error)

type Option func(*config)

// WithClockSkew sets the leeway on exp/nbf/iat (RS-07), in seconds — never
// configurable in minutes.
func WithClockSkew(d time.Duration) Option

func WithIssuer(iss string) Option

// Claims is populated only once every check has passed.
type Claims struct {
	Subject   string
	ClientID  string
	Audience  []string
	Scope     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	JTI       string
}

// ValidateAccessToken checks the allow-list, the full claim set, typ ==
// "at+jwt" (RFC 9068) and that Audience contains wantAudience (RS-19). An
// ID token presented here fails on typ (RS-08) — checked as well as aud,
// so neither claim alone is the one misconfiguration away from accepting
// the other token type.
func (v *Validator) ValidateAccessToken(ctx context.Context, raw, wantAudience string) (Claims, error)

// ValidateIDToken checks the same set with typ == "id_token" and Audience
// == {clientID}. Never accepted where ValidateAccessToken is required.
func (v *Validator) ValidateIDToken(ctx context.Context, raw, clientID string) (Claims, error)

// NewJWKSSource builds a KeySource that fetches and caches a remote JWKS,
// refetching on an unknown kid at most refetchLimit times per
// refetchWindow (RS-09) — the limit that keeps a flood of forged-kid
// tokens from turning the resource server into a DoS amplifier against
// the AS.
func NewJWKSSource(jwksURL string, httpClient *http.Client, refetchLimit int, refetchWindow time.Duration) *JWKSSource
```

---

## 8. `internal/audit` — event schema and emission (RI-03)

```go
package audit

type EventType string

const (
	EventLoginAttempt   EventType = "login_attempt"
	EventConsentGranted EventType = "consent_granted"
	EventTokenIssued    EventType = "token_issued"
	EventRefreshReuse   EventType = "refresh_reuse_detected"
	EventCodeReplay     EventType = "code_replay_detected" // RS-04's sibling to EventRefreshReuse
	EventRevocation     EventType = "revocation"
	EventRateLimited    EventType = "rate_limited"
	EventGatewayRejected EventType = "gateway_rejected"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

// Event is one audit record, versioned so a consumer evolves independently
// of this project's Go types (RF-09).
type Event struct {
	SchemaVersion int
	Type          EventType
	Outcome       Outcome
	Subject       string // canonicalized (RS-35) or ""
	ClientID      string
	RequestID     string
	SourceAddr    string
	Detail        map[string]string // caller's contract: never a secret (RS-23) — Emit does not scan for one
	At            time.Time
}

// Emitter accepts an Event for delivery. Emit must never block its caller
// on a slow or unreachable sink — the bounded buffer and the drop counting
// (ADR-0017) live inside the crier-backed implementation, not in this
// interface, so a test double can be a synchronous slice with no such
// concern.
type Emitter interface {
	Emit(ctx context.Context, e Event)
}
```

`EventRefreshReuse` is emitted **in addition to**, never **instead of**, the
`RevokedReason` written on the `Family` row in the same transaction
(`oauth.FamilyStore.Rotate` + `Revoke`, ADR-0017) — the row is what survives
if this `Emitter` cannot.

---

## 9. `internal/proxy` — never imports `internal/oauth` or `internal/oidc`

```go
package proxy

// Denylist is the gateway-local revocation check (RF-06, ADR-0014).
// Implemented in internal/store/redis (#38); consulted by NewHandler
// itself (#40) on every request, after signature verification and
// before forwarding.
type Denylist interface {
	// Contains reports whether jti is revoked. A non-nil error must be
	// treated as revoked by the caller (RNF-04: infrastructure failure
	// denies) — "unknown" and "revoked" collapse to the same response.
	Contains(ctx context.Context, jti string) (bool, error)

	Add(ctx context.Context, jti string, ttl time.Duration) error
}

// Route is one proxied route's static configuration. Audience is
// required — ValidateRoute, called by NewHandler itself (#41), refuses a
// Route without one rather than silently serving requests with the
// audience check skipped.
type Route struct {
	PathPrefix string
	Upstream   *url.URL
	Audience   string
	Breaker    *bastion.Breaker // RI-02, ADR-0016: one named breaker per upstream — wired in #42, unused by #40/#41
}

// ValidateRoute is RS-19/RNF-05: a Route with no Audience must refuse to
// start. tokenvalidator.Validator.ValidateAccessToken treats an empty
// wantAudience as "no audience required" — without this check, an
// audience-less Route would silently accept a token issued for any
// other resource server behind the gateway, defeating RS-19's whole
// point (a token for RS-A refused at RS-B's route).
func ValidateRoute(route Route) error

// NewHandler builds the reverse proxy for one Route (#40). Panics if
// route fails ValidateRoute (#41) — "refuses to start," applied directly
// since nothing yet loads a Route from outside Go code for a
// startup-time error to attach to instead. It reaches tokens only
// through validator (pkg/tokenvalidator, constructed over
// keys.Keyset.AsKeySource — internal/keys, not internal/oauth) and
// denylist. This is the whole reason ADR-0001's boundary holds by
// construction: nothing here has a way to reach an oauth.Code or
// oauth.Family type.
//
// Per request: strip every inbound `X-Auth-*` header (RS-17, an
// allow-list of what survives — nothing, in that namespace, from the
// client); extract the bearer token and call
// validator.ValidateAccessToken(ctx, token, route.Audience) — RS-19's
// own cross-audience rejection, and RS-08's typ check, both already
// inside that one call; on success, consult
// denylist.Contains(claims.JTI) (RF-06) — an error here denies, the same
// as "revoked" (RNF-04); only then inject X-Auth-Subject, X-Auth-Client
// and X-Auth-Scope from the validated claims and forward via
// httputil.ReverseProxy. Any failure in that sequence is a bare 401, no
// body — RS-23/RS-25's "no internal detail" extended to the gateway's
// own auth failures.
//
// The ReverseProxy itself carries RS-20/RS-21: a custom ErrorHandler
// that never writes err's own text to the response (Go's transport
// errors embed the literal upstream address), a Transport with explicit
// dial/handshake/response-header/idle timeouts (net/http's own default
// is none), and a ModifyResponse that caps the upstream response body at
// a fixed size before any of it reaches the client. Hop-by-hop headers
// and "never follow an upstream redirect" are net/http/httputil's own
// documented behavior, not something this package adds.
//
// A nil logger discards.
func NewHandler(route Route, validator *tokenvalidator.Validator, denylist Denylist, logger *slog.Logger) http.Handler
```

---

## 10. Flow 1 — `/authorize` → login → consent → code (RF-02)

Each step's number is load-bearing where noted: reversing 1↔2 or 2↔3 turns a
config error into an open redirect (RS-28), and it compiles either way.

1. **Parse `/authorize`'s parameters. Look up `client_id`** against the
   loaded `[]identity.Client` (RF-01). Not found → render an error page.
   **No redirect issued at this step** (RS-28, step 1) — there is nowhere
   verified to send one.
2. **Exact-match `redirect_uri`** against the now-known client's
   `RedirectURIs` (RS-02). No match → render an error page. **Still no
   redirect** (RS-28, step 2).
3. From here, `redirect_uri` is verified and every further problem is
   reported *to it*, per RFC 6749 §4.1.2.1 (RS-28, step 3): `response_type
   == "code"`; `code_challenge` present with `method == "S256"` (RS-01);
   `state` present (RS-03); requested scope ⊆ the client's `Scopes`.
4. Build a `session.Challenge`, `ChallengeStore.Save`, redirect to
   `/login?challenge=<id>` — no other parameter in the query string (RS-05).
5. `GET /login` renders the form under a CSP nonce (RS-36). `POST /login`
   requires the CSRF token (RS-12a); looks up `UserStore.ByIdentifier` on the
   canonicalized identifier (RS-35); verifies the password constant-time
   against the real hash or, if `ok == false`, a dummy one computed at
   startup with current parameters (RS-14) — **inside** the Argon2id
   concurrency semaphore either way (RS-33), so the queueing time itself
   does not distinguish the two cases.
6. On success: **rotate the session id and the CSRF token — both, as two
   separate calls** (RS-12b); create or refresh the `BrowserSession`
   (RF-10, RS-31); `ChallengeStore.SetSubject`.
7. Redirect to `/consent?challenge=<id>`.
8. `GET /consent`: if `ConsentStore.Granted` already covers the requested
   scope, skip to step 10 (RF-13). Otherwise render the consent form —
   client name and requested scopes passed through `html/template`'s default
   escaping, never `template.HTML` (RS-36) — behind the same CSRF
   requirement (RS-12a).
9. On approval: `ConsentStore.Grant` with the union of any prior grant and
   the newly requested scope.
10. `ChallengeStore.Consume` (single-use, RS-05) to get the final
    `Challenge`. Generate a fresh `Code` from `crypto/rand`; `CodeStore.Save`
    bound to `client_id`, `redirect_uri`, `code_challenge`, `nonce` (RS-04,
    RS-30).
11. Redirect to `redirect_uri` with `code`, the original `state` unchanged
    (RS-03), and `iss` (RS-29).

## 11. Flow 2 — `POST /token`, `authorization_code`

1. Authenticate the client: `client_secret_basic`/`post` compared via
   `secret.Value` (RS-16, RS-15), or none required for a public client — PKCE
   is what stands in for a secret there.
2. `CodeStore.Consume(code)` — the single atomic operation (RS-04).
3. **If `Consume` fails:** call `CodeStore.TombstonedFamily(code)`. Found →
   this is a replay of a code that already succeeded once: `FamilyStore
   .Revoke(familyID, "reuse_detected")` and `audit.Emit(EventCodeReplay)` at
   high severity — RS-04's sibling to Flow 3's RS-11 handling, applied one
   step removed, since the family a code produces exists only after that
   code's first, successful consumption. Either way — found or not —
   respond `invalid_grant` (RS-25): the client cannot tell a replay from an
   expired code, by design.
4. **If `Consume` succeeds:** re-verify the returned `Code`'s `ClientID` and
   `RedirectURI` match this request exactly, and `code_verifier` against
   `CodeChallenge` with S256 (RS-01, RS-04). Any mismatch → `invalid_grant`.
5. `keys.Keyset.Signing(now)` to get the active key; sign the access token
   with the requested resource server's audience, `typ: at+jwt` (RS-06,
   RS-07, RS-08).
6. If the client's grant types include `refresh_token`:
   `FamilyStore.CreateFamily` with a fresh opaque token (RS-10).
7. `CodeStore.Tombstone(code, familyID, ttl=maxAccessTokenTTL)` — **after**
   issuance, not before (§2.1's stated residual covers the window this
   still leaves).
8. `audit.Emit(EventTokenIssued)`.
9. Respond with `Cache-Control: no-store` (RS-26) and the fixed error
   shape on any failure above (RS-25).

## 12. Flow 3 — `POST /token`, `refresh_token` (RS-11, ADR-0012, RS-34)

1. Authenticate the client if confidential (RS-16).
2. `hash = SHA-256(presented token)` (RS-10) — the raw value is never looked
   up directly.
3. `FamilyStore.Lookup(hash)`. Not found, or `Family.RevokedAt != nil` →
   `invalid_grant`. Otherwise check RS-34's bindings: `Family.ClientID`
   equals the authenticated client; the requested scope (default: the
   family's own) is a subset of `Family.Scope` — a superset is
   `invalid_scope`, never a silent widening.
4. Generate `next RefreshToken` (fresh opaque value, hashed).
5. `FamilyStore.Rotate(hash, next)` — the atomic compare-and-set (RS-11).
6. **`consumed == false`:** the presented token was already used once. This
   is reuse, **not** an ordinary error — **no grace window** (ADR-0012):
   `FamilyStore.Revoke(familyID, "reuse_detected")`, `audit.Emit
   (EventRefreshReuse)` at high severity, respond `invalid_grant`.
7. **`consumed == true`:** this is the legitimate exchange. Sign a new
   access token (as in Flow 2, step 5); the response carries `next`'s raw
   value once — it is never retrievable again (RS-10).
8. Respond with `Cache-Control: no-store` (RS-26).

---

## 13. Flow 4 — `POST /revoke` (RFC 7009, RF-06, RF-13, ADR-0014)

1. Authenticate the client if confidential (RS-16) — shared with Flow 2/3
   through the same `authenticateClient` function.
2. `tokenvalidator.ValidateForRevocation(token)` — the same signature
   verification and claim set `ValidateAccessToken` (Flow 1-3's own
   gateway-side check) requires, minus the audience claim: `/revoke`'s
   caller is the client the token was issued to, not a resource server
   enforcing RS-19 for one particular audience.
3. **Verifies as an access token:** `Claims.ClientID` must equal the
   authenticated client (RFC 7009 §2.1) — otherwise respond success
   without revoking anything (step 6). Otherwise, `ttl =
   Claims.ExpiresAt - now`; if `ttl > 0`, `Denylist.Add(Claims.JTI, ttl)`
   (ADR-0014: the gateway-local write side) and emit `EventRevocation`.
4. **Fails verification** (bad signature, wrong `typ`, expired, or not a
   JWS at all — a refresh token is an opaque string, never JWS-shaped):
   treat `token` as a refresh token instead. `hash =
   SHA-256(token)`; `FamilyStore.Lookup(hash)`. Not found → success
   (step 6); found → `Family.ClientID` must equal the authenticated
   client (RFC 7009 §2.1), otherwise success without revoking anything.
5. Otherwise `FamilyStore.Revoke(familyID, "revoked_by_client")` (#36's
   same idempotent UPDATE RS-11's reuse path already uses) and, if the
   family was not already revoked, emit `EventRevocation`.
6. Respond `200`, empty body, `Cache-Control: no-store` — always, RFC
   7009 §2.2's own ambiguity: a client probing values at this endpoint
   learns nothing from the response shape about whether a value ever
   corresponded to a real token.

**Scope of the guarantee, stated rather than implied:** revoking an
access token here only ever reaches the gateway's own denylist read
(ADR-0014) — not yet implemented (M6). A resource server validating
independently (RS-18) keeps accepting a revoked access token until its
own `exp`. RF-06's own wording already says this; this flow does not
claim anything stronger.

---

## 14. What this surfaced

Per the method's own claim (`foundation/method/00-before-code.md`): writing
signatures before bodies is supposed to find design problems while they are
still cheap. Two did surface here, and both are addressed above rather than
left for implementation to discover:

- **No package for configuration loading existed in REQUIREMENTS §7's tree**,
  despite `CONTRIBUTING.md`'s commit scopes and issue #12 already assuming one.
  Added as `internal/config` in §1 above; REQUIREMENTS §7's tree should gain
  the same line in a small follow-up edit rather than staying silently out of
  date with this document.
- **Code replay detection has the same two-write residual refresh rotation
  does not.** `FamilyStore.Rotate` closes refresh reuse in one atomic
  operation (RS-11); `CodeStore` cannot, because the family a code produces
  does not exist until *after* the code is consumed — `Tombstone` is
  necessarily a second call. §2.1 and Flow 2 step 7 state the resulting
  window plainly rather than implying `CodeStore` gives RS-04 the same
  one-operation guarantee RS-11 gets.

---

## 15. `internal/rbac` — permission evaluation (RF-05, #39)

```go
package rbac

// Permissions maps a role name to its own fixed set of permissions —
// RF-05's other half, the one that depends on who the user is rather
// than what the client asked for. Static, versioned configuration, the
// same shape identity.Client's own Scopes field already is for RF-01.
type Permissions map[string][]string

// Authorizer evaluates RF-05 against one Permissions vocabulary.
type Authorizer struct{ /* ... */ }

func New(roles Permissions) *Authorizer

// Allowed is RF-05 itself: permission is granted only when it appears in
// BOTH scope and role's own permission set — never from either alone.
func (a *Authorizer) Allowed(permission string, scope []string, role string) bool

// RequirePermission is REQUIREMENTS §8's own Decorator example:
// RequirePermission("task:write")(handler). A denied request gets 403,
// empty body — no detail about which half of the intersection failed.
func (a *Authorizer) RequirePermission(permission string) func(http.Handler) http.Handler

// WithScope/ScopeFrom and WithRole/RoleFrom are the one seam this
// package depends on: a context.Context carrying the authenticated
// request's own granted scope and role, set by whatever validates the
// bearer token before RequirePermission's handler runs. This package
// has no opinion on how that happens — ADR-0006's own [auth] → [rbac]
// chain order is internal/proxy's job, M6, not yet built; these two
// functions are what lets RequirePermission be fully testable (a table
// over scope/role combinations) without that chain existing yet.
func WithScope(ctx context.Context, scope []string) context.Context
func ScopeFrom(ctx context.Context) []string
func WithRole(ctx context.Context, role string) context.Context
func RoleFrom(ctx context.Context) string
```

The role vocabulary itself (which permission strings exist, which roles
hold which) is deliberately not this package's decision — `cmd/seed`'s
own `seedRoles` already calls `"admin"` and `"user"` provisional
placeholders for exactly that reason. Whoever constructs the `Authorizer`
(M6's gateway wiring) supplies the real `Permissions` map.
