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

**This is the plan this document carried through M2/M4; it is not what was
built.** All three grants — `handleAuthorizationCode` (M2), `handleRefreshToken`
(M4), `handleClientCredentials` (M8, #49) — are methods on `tokenHandler`
(`cmd/usher/token.go`), dispatched by a `switch` in `ServeHTTP`, never
`grant.Strategy` implementations behind a Facade. `grant.go`'s own `Strategy`
interface above has zero implementations anywhere in this codebase.

REQUIREMENTS §8 itself permits this ("a pattern the phase does not need is
not introduced for this table's sake"): the direct-dispatch shape gives each
grant its own isolated method with no shared mutable state between them,
which is the actual property Strategy would have bought, at a smaller cost
— no interface, no separate package boundary to cross for three methods
that all live in the one file already wiring `/token`'s shared client
authentication. `internal/oauth/grant` itself is consequently dead code:
kept here, not deleted, because removing an unused package is its own
decision, not a side effect of documenting that it was never adopted.

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
	Breaker    *bastion.Breaker // RI-02, ADR-0016: one named breaker per upstream (#42). nil is a valid "no breaker configured for this route."
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
// If route.Breaker is set, the outbound call (Transport.RoundTrip, not
// the whole request) runs through it via bastion.Execute (#42,
// ADR-0016). bastion.ErrOpenState and bastion.ErrTooManyRequests reach
// ErrorHandler as ordinary RoundTrip errors — mapped there to 503 +
// Retry-After, never the bare 502 a genuine upstream failure gets
// (ADR-0016 rule 1). No internal retry wraps the breaker, so exactly one
// outbound attempt happens per incoming request regardless of its
// outcome — what makes "the rate limiter runs once, on the way in"
// (ADR-0016 rule 2) hold for whatever outer middleware wraps this
// handler, without this package needing to know what that middleware is.
// Retry-After is a fixed, conservative value: bastion does not expose
// its own configured WithOpenTimeout for a precise one — reported back
// per ADR-0016 ("usher becomes bastion's first real integration...").
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
   `state` present (RS-03); requested scope ⊆ the client's `Scopes`;
   `prompt` is `""`, `"none"` or `"login"` — nothing else, including OIDC
   Core's general space-delimited list (RF-11, ADR-0020); `max_age`, if
   present, is a non-negative integer of seconds.
4. Build a `session.Challenge` carrying `prompt`/`max_age` unchanged
   alongside `nonce`, `ChallengeStore.Save`, redirect to
   `/login?challenge=<id>` — no other parameter in the query string (RS-05).
5. **`GET /login` first decides whether interaction is needed at all**
   (RF-10/RF-11, ADR-0020): it reads the browser's own session cookie
   (`session.SessionStore`). A session that is present, that `prompt` never
   asked to override (`"login"`), and that `max_age` (if set) does not
   consider stale is reused silently — skip to step 6 with that session's
   own subject and `AuthTime`, no form rendered. Otherwise: `prompt ==
   "none"` redirects `login_required` to the client (same shape as step
   11); anything else renders the form under a CSP nonce (RS-36). `POST
   /login` requires the CSRF token (RS-12a); looks up
   `UserStore.ByIdentifier` on the canonicalized identifier (RS-35);
   verifies the password constant-time against the real hash or, if `ok ==
   false`, a dummy one computed at startup with current parameters
   (RS-14) — **inside** the Argon2id concurrency semaphore either way
   (RS-33), so the queueing time itself does not distinguish the two
   cases.
6. On a fresh password login: **rotate the session id and the CSRF
   token — both, as two separate calls** (RS-12b); create or refresh the
   `BrowserSession` (RF-10, RS-31) with `AuthTime = now`. Either way (fresh
   login or step 5's silent reuse): `ChallengeStore.SetAuthenticated`
   records the subject and that `AuthTime` on the challenge — the value
   Flow 2 step 6 later signs into the `id_token`'s own `auth_time` (RF-11).
7. Redirect to `/consent?challenge=<id>`.
8. `GET /consent`: if `ConsentStore.Granted` already covers the requested
   scope, skip to step 10 (RF-13). Otherwise, if `prompt == "none"`
   (ADR-0020): redirect `consent_required` to the client — consent is
   genuinely needed and prompt forbids asking for it. Otherwise render the
   consent form — client name and requested scopes passed through
   `html/template`'s default escaping, never `template.HTML` (RS-36) —
   behind the same CSRF requirement (RS-12a).
9. On approval: `ConsentStore.Grant` with the union of any prior grant and
   the newly requested scope.
10. `ChallengeStore.Consume` (single-use, RS-05) to get the final
    `Challenge`. Generate a fresh `Code` from `crypto/rand`; `CodeStore.Save`
    bound to `client_id`, `redirect_uri`, `code_challenge`, `nonce` (RS-04,
    RS-30) and carrying `AuthTime` unchanged from the challenge (RF-11) —
    `prompt`/`max_age` themselves are spent by this point and go no
    further; only the `AuthTime` they already governed does.
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
6. If the granted scope includes `openid`: sign an id_token with the same
   key, `typ: id_token`, `aud` = the client alone (never the resource
   server's audience — RS-08, RF-03, RF-11), `nonce` echoed unchanged from
   the `Code` when one was bound at `/authorize`, omitted otherwise
   (RS-30), and `auth_time` from the `Code`'s own `AuthTime` (RF-11, #47,
   ADR-0020) — omitted only for a `Code` built without one, which no real
   `/login`→`/consent` flow produces any more. This typ header, not the
   differing `aud`, is what makes Flow 1's gateway reject an id_token
   presented as a bearer credential — `aud` is never inspected if `typ`
   already failed.
7. If the client's grant types include `refresh_token`:
   `FamilyStore.CreateFamily` with a fresh opaque token (RS-10).
8. `CodeStore.Tombstone(code, familyID, ttl=maxAccessTokenTTL)` — **after**
   issuance, not before (§2.1's stated residual covers the window this
   still leaves).
9. `audit.Emit(EventTokenIssued)`.
10. Respond with `Cache-Control: no-store` (RS-26) and the fixed error
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
   value once — it is never retrievable again (RS-10). No id_token is
   reissued here (Flow 2, step 6) — OIDC Core leaves that optional on
   refresh, and nothing in REQUIREMENTS.md or the threat model asks for
   it.
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
// chain order is internal/proxy.NewHandler's own job (#104's follow-up,
// Flow 9 below): it validates the token, resolves the subject's role,
// calls WithRole(WithScope(ctx, claims.Scope), role), and passes the
// result to RequirePermission(route.Permission). These two functions
// are what let RequirePermission be fully testable (a table over
// scope/role combinations) without that chain existing — which is also
// exactly how internal/proxy's own tests use them today.
func WithScope(ctx context.Context, scope []string) context.Context
func ScopeFrom(ctx context.Context) []string
func WithRole(ctx context.Context, role string) context.Context
func RoleFrom(ctx context.Context) string
```

The role vocabulary itself (which permission strings exist, which roles
hold which) is deliberately not this package's decision — `cmd/seed`'s
own `seedRoles` already calls `"admin"` and `"user"` provisional
placeholders for exactly that reason. `cmd/usher/main.go` constructs the
real `Authorizer` (`gatewayRolePermissions`) and the `RoleLookup` that
resolves a subject to a role (`userRoleLookup`, adapting
`identity.UserStore` — `internal/proxy` never imports `internal/identity`
directly, the same boundary this file's own package doc already
promises).

---

## 16. Flow 5 — `GET /userinfo` (RS-08, RS-26, #45)

1. Extract the bearer token from `Authorization: Bearer ...`. Missing or
   empty → 401.
2. `tokenvalidator.ValidateAccessToken(token, userinfoAudience)` —
   `userinfoAudience` derived from the issuer (`{issuer}/userinfo`), not a
   separate config field: the same `*Validator` instance `/revoke` builds
   (Flow 4), since the audience is a call-time parameter on that type, not
   something baked into the validator itself. Fails verification (bad
   signature, wrong `typ`, expired, or missing this audience) → 401, same
   bare body as every other cause (RS-23/RS-25) — a caller cannot tell
   "no token" from "wrong `typ`" from "wrong `aud`" from "expired" by
   response shape.
3. Respond `200` with `{"sub": Claims.Subject}` — the one claim usher's
   own `identity.User` has anything to say about; no name, email or other
   profile data exists anywhere in this project's `User` model to put
   behind a scope it never asked the user to consent to.
4. Respond with `Cache-Control: no-store` (RS-26) on both the success and
   the 401 paths.

**Where the userinfo audience comes from:** Flow 2 step 6 adds it to an
access token's `aud` alongside the resource server's own, whenever the
granted scope includes `openid` — never in place of the resource
server's audience, and never for a token issued without `openid` in
scope. A token issued for a request that never asked for `openid` is
therefore refused here even though it is otherwise perfectly valid: aud
mismatch, not a signature or claims-shape problem.

---

## 17. `GET /.well-known/openid-configuration` (RS-29, RF-11, #46)

A static document (`discoveryHandler`, `cmd/usher/discovery.go`) built
from facts about handlers that already exist elsewhere in this binary —
it has no logic of its own to get wrong. Every field is either a literal
this project can back with an existing test (`response_types_supported`:
`["code"]`, `authorize.go`'s own check; `grant_types_supported`:
`["authorization_code", "refresh_token"]`, `token.go`'s own dispatch;
`code_challenge_methods_supported`: `["S256"]`; `token_endpoint_auth_methods
_supported`: `["none", "client_secret_basic", "client_secret_post"]`) or
derived directly from another package's own allow-list rather than
hand-typed (`id_token_signing_alg_values_supported` from
`pkg/tokenvalidator`'s `RS256`/`ES256` constants, RS-06).

**What is deliberately absent, and why:**

- No `registration_endpoint` — RF-01's clients are static configuration,
  never dynamically registered.
- No `introspection_endpoint` — REQUIREMENTS §3.2 names RFC 7662 as a
  protocol surface; nothing implements it.
- No `prompt_values_supported` or anything naming `max_age` — RF-11 names
  both, but #47 is where either gets parsed. Advertising a capability
  before the code behind it exists would make this document briefly
  false the moment it was written, which is exactly what "advertises
  only what is implemented" (this issue's own framing) rules out.
- `scopes_supported` is `["openid"]` alone, not the longer list a
  client's own registered `Scopes` (RF-01) might contain — `openid` is
  the only value any part of this server treats as meaningful (Flow 2
  step 6's own audience gate); `profile`, say, triggers nothing, so
  claiming it here would be a capability this project does not have.

No `Cache-Control: no-store`: REQUIREMENTS §7.2's own table marks
`/.well-known/*, JWKS` `no-store: no` — a discovery document is not the
credential response RS-26 means.

---

## 18. Flow 6 — `GET`/`POST /logout` (RS-27, RS-31, ADR-0021, #48)

REQUIREMENTS §7.2's own table has no row for this route; the choices below
are this issue's own, made consistently with the rows that exist rather
than inventing a new shape.

1. `GET /logout` renders a confirmation form carrying a fresh CSRF token
   (RS-12a) — the same browser-form group `/login` and `/consent` are in,
   same reasoning (double-submit CSRF needs the token minted on a safe
   method first).
2. `POST /logout`, after the CSRF check: **delete the server-side session
   first** (`SessionStore.Delete`, RS-31) — before anything else is
   written to the response, so a crash or a slow client between the
   delete and the reply still leaves the session gone. Idempotent: no
   session cookie, or one the store no longer recognizes, is not an error
   (the same RFC 7009 ambiguity Flow 4's own `/revoke` already applies).
3. Clear the session cookie (`ExpiredSessionCookie`, `MaxAge=-1`) and set
   `Clear-Site-Data` (RS-27) — both the browser half, defense in depth
   over step 2, never the mechanism. `Clear-Site-Data` carries `"cache",
   "storage"` only, never `"cookies"` (ADR-0021) — usher's own `__Host-`
   session cookie is already gone by step 3's own first half regardless,
   and omitting `cookies` is what keeps this logout from also clearing
   cookies other applications on the same registrable domain set for
   themselves.
4. Render a plain confirmation page.

No rate limiter is wired (the same deferred-and-documented choice
`tokenGroup` and `jwksGroup` already make for their own routes): no RS-/RF-
id here asks for one.

---

## 19. Flow 7 — `POST /token`, `client_credentials` (RFC 6749 §4.4, REQUIREMENTS §3.1, #49)

The one grant with no resource owner at all, sharing `handleAuthorizationCode`
and `handleRefreshToken`'s own client authentication (`authenticateClient`,
`ServeHTTP`) but none of their PKCE, code or redirect machinery — none of
it protects anything when there is no browser step to intercept.

1. Authenticate the client (shared with Flow 2/3/4). A **public** client
   reaches this point successfully authenticated — `authenticateClient`
   never required a secret from one — so confidentiality is checked here
   instead: not confidential → `unauthorized_client` (RFC 6749 §5.2).
   Confidential but `client_credentials` not in its own registered
   `GrantTypes` → the same error; being confidential is necessary, not
   sufficient.
2. Requested scope ⊆ the client's own registered `Scopes` → `invalid_scope`
   otherwise, the same check `/authorize` already applies to
   `authorization_code` (REQUIREMENTS §3.1's "scopes limited to the
   client's registration").
3. `issueAccessToken(client, client.ID, scope)` — the same function Flow 2
   step 5 and Flow 3 step 7 share, with `client.ID` standing in for the
   subject a user-driven grant would have. If `scope` happens to include
   `openid` (a client registered for both `client_credentials` and OIDC
   scopes, however unusual), the token still gets the RS-08 userinfo
   audience Flow 2 step 6 adds — nothing here excludes it — but this
   handler never calls `issueIDToken` regardless, so no `id_token` is
   ever produced: there is no user for one to describe.
4. Respond with `Cache-Control: no-store` (RS-26, shared with every other
   `/token` grant). No `refresh_token`: this grant has no issuance path
   for one, unlike `authorization_code`'s conditional one — the client
   can always obtain a fresh access token by presenting its own
   credentials again.

---

## 20. Flow 8 — `POST /introspect` (RFC 7662, RS-25, RS-26, #50)

Shares `/revoke`'s own dual-check shape exactly (Flow 4, §13): authenticate
the client, try the presented value as an access token first
(`tokenvalidator.ValidateForRevocation`), fall back to a refresh-token
lookup on failure. The two endpoints answer the same underlying question
about the same two token kinds; only what a *genuinely active* result
looks like differs.

1. Authenticate the client (shared with every other `/token`-adjacent
   route). Missing or wrong credentials → `invalid_client`, same as
   `/revoke` and `/token` — **not** folded into `{"active": false}`: RFC
   7662 §2.1 requires the caller to authenticate, and failing that is a
   distinct, reported error.
2. `token` missing → `invalid_request`, before authentication is even
   checked, mirroring `/revoke`'s own order.
3. Verifies as an access token (`ValidateForRevocation`): `Claims
   .ClientID` must equal the authenticated client, and the claimed `exp`
   must still be in the future by this handler's own clock (not just
   within `ValidateForRevocation`'s skew tolerance — the same `ttl <= 0`
   edge case Flow 4 step 3 documents, decided here as inactive rather
   than merely "nothing left to deny-list"). Either failing → inactive.
   Otherwise respond `active: true` with the full claim set this project
   can answer truthfully: `scope`, `client_id`, `token_type: "Bearer"`,
   `sub`, `iss`, `aud`, `exp`, `iat`, `jti`.
4. **Fails verification** (bad signature, wrong `typ`, expired beyond
   skew, or not a JWS at all): treat `token` as a refresh token instead.
   `FamilyStore.Lookup` — not found (which already folds in "past its own
   idle or absolute lifetime," the same ambiguity Flow 3's own `invalid
   _grant` relies on) → inactive. Found but `Family.ClientID` does not
   match the authenticated client → inactive (RFC 7662's own binding
   check, the same one Flow 4 step 4 already applies). `RevokedAt` set,
   or this exact token value's own `ConsumedAt` set (already rotated
   away by a real refresh exchange, Flow 3 step 5) → inactive. Otherwise
   respond `active: true` with `scope`, `client_id`, `sub`, `iss`, `exp`
   (the family's own absolute lifetime) — there is no per-token `iat` or
   `jti` to report for an opaque value.
5. Every inactive cause above produces the identical body,
   `{"active":false}` — the zero `introspectBody{}`, never a
   hand-written literal that could drift from what the active branches
   above actually populate (RS-25's ambiguity principle, the same one
   `/token`'s `invalid_grant` and `/revoke`'s always-200 already apply).
6. Respond with `Cache-Control: no-store` (RS-26) — the same `tokenGroup`
   `/token` and `/revoke` already carry; no new route group.

## 21. Flow 9 — `GET`/`POST /api/**` (the gateway, ADR-0007, ADR-0013, #104)

`internal/proxy.NewHandler` was built and unit-tested in #40–#42, but
`cmd/usher/main.go` never instantiated it — there was no live `/api/**`
route in the real binary until #104. Mounted conditionally
(`GatewayUpstream != nil`, the same "absent by default" shape `Emitter`
already has): a deployment with nothing to proxy to — this repository's
own test suite included — gets a router with no gateway at all, rather
than one guaranteed to fail every request.

1. `chi.Mux.Mount("/api", ...)` wraps `proxy.NewHandler`'s result in
   `http.StripPrefix("/api", ...)`: the one upstream wired for the MVP,
   `cmd/resource-server`, defines `/widgets`, never `/api/widgets` — the
   prefix is this gateway's own convention, not the upstream's concern.
   `NewHandler` itself only rewrites `Scheme`/`Host`; it never touches
   the path, so whoever mounts it decides this, not `internal/proxy`.
2. Strip every inbound `X-Auth-*` header (RS-17) before anything else
   reads the request.
3. Extract the bearer token; missing → 401, same body (none) as every
   other failure mode below (RS-23/RS-25's "no internal detail" applied
   here too — a caller cannot distinguish "missing" from "invalid" from
   "revoked" by response shape).
4. Validate it with the same `bearerValidator` `/revoke`, `/introspect`
   and `/userinfo` already share (Flow 4, Flow 5, Flow 8) — same
   algorithm allow-list (RS-06), same issuer, same clock — against
   *this route's own* `Audience` (RS-19: a token minted for one resource
   server is refused at another's route, never silently accepted
   because some route's check was skipped). Fails → 401.
5. Consult the gateway-local denylist (RF-06, ADR-0014) by the token's
   `jti` — the same store `/revoke` writes to (`routerDeps.Denylist`,
   constructed once, read here and written there). A denylist error
   collapses to "revoked" (RNF-04: infrastructure failure denies), never
   to "allowed." Found or errored → 401.
6. RF-05, the `[rbac]` half of REQUIREMENTS §7.2's `/api/**` row, built
   on `internal/rbac`'s own intended seam rather than a second,
   parallel mechanism: resolve the subject's role through `RoleLookup`
   (`userRoleLookup` in `cmd/usher/main.go`, adapting
   `identity.UserStore.ByID` — `internal/proxy` never imports
   `internal/identity` directly), attach it and the token's own scope
   to the request context (`rbac.WithRole(rbac.WithScope(ctx,
   claims.Scope), role)`), and run the rest of this handler through
   `authorizer.RequirePermission(route.Permission)`. A role-lookup
   failure → 401 (RNF-04 again: the subject itself could not be
   resolved, closer to "an invalid credential" than to "a known
   identity without permission"); a resolved role lacking the
   permission → 403, `RequirePermission`'s own response, not a second
   one this handler writes itself. `authorizer == nil` skips this step
   entirely — the same "absent is a deliberate, valid choice"
   `route.Breaker` already has; a non-nil `authorizer` with an empty
   `route.Permission` panics instead (RF-05's own "wiring mistake must
   be loud," the same reasoning `ValidateRoute`'s `Audience` check
   already applies).
7. Inject `X-Auth-Subject`, `X-Auth-Client`, `X-Auth-Scope` (RI-04) —
   only after every check above passed, and only these three headers in
   that namespace ever get set, since step 2 already guaranteed nothing
   else under it survived from the client.
8. Forward the original `Authorization` header unchanged (ADR-0007): the
   resource server re-validates the same token itself, with its own
   audience and its own JWKS fetch (RS-18) — it never trusts step 7's
   headers for an authorization decision (`RI-04`'s own contract, which
   this gateway cannot enforce on a consumer reached outside it).
9. The round trip to the upstream runs through one named `bastion.Breaker`
   (ADR-0016, RI-02) and RS-21's explicit timeouts
   (`newUpstreamTransport`). A breaker rejection (`ErrOpenState`,
   `ErrTooManyRequests`) answers `503` + `Retry-After`, never the bare
   `502` a genuine dial/timeout failure gets (RS-20) — "the circuit is
   open" and "the upstream is down" are different facts, and a caller
   retrying immediately against a `502` would be doing exactly what the
   breaker exists to stop. Neither response leaks the upstream's own
   host, port or a stack trace.
10. The upstream's response body is capped at 10 MiB before any of it
    reaches the client (RS-21) — a misbehaving or malicious upstream
    streaming indefinitely cannot exhaust the gateway's own memory.

**This deployment's own role vocabulary** (`gatewayRolePermissions` in
`cmd/usher/main.go`) grants both seeded roles, `admin` and `user`
(`cmd/seed`'s own `seedRoles` calls both "provisional placeholders"),
the one permission this route checks, `widgets:read` — there is no
product reason in this repository to restrict an ordinary user from a
read-only demo resource. RF-05 is still genuinely enforced: a role
absent from the map, or without this permission, is refused, proven in
`internal/proxy`'s own test suite with a role neither seeded role uses.
`demo-client`'s own registered scopes (`clients.dev.json`) include
`widgets:read` for the same reason they include `openid` — RF-05's
intersection needs the permission in the token's own granted scope, not
only in the role's permissions; a client never registered for it could
never carry it regardless of role.

**Not built here:** the per-token/per-account rate limit REQUIREMENTS
§7.2's `/api/**` row also names, left unwired for the same "defer, do
not invent a weighting scheme no RS-/RF- id asks for yet" reason
`tokenGroup` already gives for `/token`.
