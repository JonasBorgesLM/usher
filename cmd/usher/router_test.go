package main

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/internal/session"
)

// weakParams is a small, fast Argon2id calibration for tests -- the real
// DefaultParams would make every test in this file slow for no benefit, the
// same reasoning internal/identity's own weakParams (unexported there, so
// not reusable from this package) documents.
var weakParams = identity.Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

const (
	testIdentifier = "alice@example.com"
	testPassword   = "right password"
)

type fakeUserStore struct{ users map[string]identity.User }

func newFakeUserStore(t *testing.T) *fakeUserStore {
	t.Helper()
	hash, err := identity.HashPassword(testPassword, weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return &fakeUserStore{users: map[string]identity.User{
		testIdentifier: {ID: "user-1", Identifier: testIdentifier, PasswordHash: hash},
	}}
}

func (f *fakeUserStore) ByIdentifier(_ context.Context, identifier string) (identity.User, bool, error) {
	u, ok := f.users[identifier]
	return u, ok, nil
}

func (f *fakeUserStore) UpdateHash(context.Context, string, string) error { return nil }

// fakeSessionStore is session_test.go's own fixture, reimplemented here:
// internal/session's version is unexported to that package, and this
// package needs the same small stand-in to build a real router without a
// real Redis.
type fakeSessionStore struct {
	sessions map[string]session.BrowserSession
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{sessions: map[string]session.BrowserSession{}}
}

func (f *fakeSessionStore) Save(_ context.Context, s session.BrowserSession) error {
	f.sessions[s.ID] = s
	return nil
}

func (f *fakeSessionStore) Get(_ context.Context, rawID string) (session.BrowserSession, error) {
	s, ok := f.sessions[rawID]
	if !ok {
		return session.BrowserSession{}, session.ErrSessionNotFound
	}
	return s, nil
}

func (f *fakeSessionStore) Delete(_ context.Context, rawID string) error {
	delete(f.sessions, rawID)
	return nil
}

type fakeChallengeStore struct {
	challenges map[string]session.Challenge
}

func newFakeChallengeStore() *fakeChallengeStore {
	return &fakeChallengeStore{challenges: map[string]session.Challenge{}}
}

func (f *fakeChallengeStore) Save(_ context.Context, c session.Challenge) error {
	f.challenges[c.ID] = c
	return nil
}

func (f *fakeChallengeStore) Get(_ context.Context, id string) (session.Challenge, error) {
	c, ok := f.challenges[id]
	if !ok {
		return session.Challenge{}, session.ErrChallengeNotFound
	}
	return c, nil
}

func (f *fakeChallengeStore) SetAuthenticated(_ context.Context, id, subject string, authTime time.Time) error {
	c, ok := f.challenges[id]
	if !ok {
		return session.ErrChallengeNotFound
	}
	c.Subject = subject
	c.AuthTime = authTime
	f.challenges[id] = c
	return nil
}

func (f *fakeChallengeStore) Consume(_ context.Context, id string) (session.Challenge, error) {
	c, ok := f.challenges[id]
	if !ok {
		return session.Challenge{}, session.ErrChallengeNotFound
	}
	delete(f.challenges, id)
	return c, nil
}

// fakeCodeStore is a small, controllable stand-in for oauth.CodeStore --
// its real atomicity is proven elsewhere (internal/store/redis's own
// integration tests, #29); this package's tests exercise /consent's
// issuance and /token's consumption of the same value, not the store.
type fakeCodeStore struct {
	codes      map[string]oauth.Code
	tombstones map[string]string
}

func newFakeCodeStore() *fakeCodeStore {
	return &fakeCodeStore{codes: map[string]oauth.Code{}, tombstones: map[string]string{}}
}

func (f *fakeCodeStore) Save(_ context.Context, c oauth.Code) error {
	if _, exists := f.codes[c.Value]; exists {
		return oauth.ErrCodeExists
	}
	f.codes[c.Value] = c
	return nil
}

func (f *fakeCodeStore) Consume(_ context.Context, value string) (oauth.Code, error) {
	c, ok := f.codes[value]
	if !ok {
		return oauth.Code{}, oauth.ErrCodeNotFound
	}
	delete(f.codes, value)
	return c, nil
}

func (f *fakeCodeStore) Tombstone(_ context.Context, value, familyID string, _ time.Duration) error {
	f.tombstones[value] = familyID
	return nil
}

func (f *fakeCodeStore) TombstonedFamily(_ context.Context, value string) (familyID string, found bool, err error) {
	familyID, found = f.tombstones[value]
	return familyID, found, nil
}

// testDeps builds routerDeps for a real *chi.Mux over fakes -- the fakes
// are proven-elsewhere business logic over Redis-backed interfaces
// (internal/session's own tests, #19/#20); what this file tests is the
// router's own composition, not the stores.
func testDeps(t *testing.T) routerDeps {
	t.Helper()
	hasher, err := identity.NewHasher(4, time.Second, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	auth, err := identity.NewAuthenticator(newFakeUserStore(t), hasher, weakParams)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	secretValue, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatalf("csrf.GenerateSecret: %v", err)
	}
	protector, err := csrf.New(secretValue)
	if err != nil {
		t.Fatalf("csrf.New: %v", err)
	}
	return routerDeps{
		Authenticator:      auth,
		Sessions:           newFakeSessionStore(),
		Challenges:         newFakeChallengeStore(),
		CSRFProtector:      protector,
		LoginLimiter:       ratelimit.New(1000, 1000), // generous: not what this file's tests exercise
		AuthorizeLimiter:   ratelimit.New(1000, 1000), // generous: not what this file's tests exercise
		Consents:           newFakeConsentStore(),
		Codes:              newFakeCodeStore(),
		Issuer:             "https://usher.test",
		ChallengeTTL:       5 * time.Minute,
		AuthCodeTTL:        time.Minute,
		AccessTokenTTL:     5 * time.Minute,
		SessionIdleTTL:     time.Hour,
		SessionAbsoluteTTL: 24 * time.Hour,
		Now:                func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
}

// testDepsWithSink is testDeps plus an audit.MemorySink wired in as the
// Emitter, for the tests that assert on what got emitted (RF-09). Kept
// separate from testDeps so the other tests in this file -- which do not
// care about audit events -- are not forced to thread a sink through.
func testDepsWithSink(t *testing.T) (routerDeps, *audit.MemorySink) {
	t.Helper()
	deps := testDeps(t)
	sink := audit.NewMemorySink()
	deps.Emitter = sink
	return deps, sink
}

// walkedRoute is one entry chi.Walk reports against a built *chi.Mux.
type walkedRoute struct {
	method, pattern string
}

func walkRoutes(t *testing.T, mux *chi.Mux) []walkedRoute {
	t.Helper()
	var routes []walkedRoute
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, walkedRoute{method: method, pattern: route})
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	return routes
}

// unclassifiedRoutes is the property check itself: every route chi.Walk
// finds on mux must have an entry in routeGroups. Both
// TestRouteProperties_* tests below call this one function, so the
// negative control proves the actual check, not a copy of it.
func unclassifiedRoutes(t *testing.T, mux *chi.Mux) []string {
	t.Helper()
	var uncovered []string
	for _, rt := range walkRoutes(t, mux) {
		if _, ok := routeGroups[rt.pattern]; !ok {
			uncovered = append(uncovered, rt.method+" "+rt.pattern)
		}
	}
	return uncovered
}

// TestRouteProperties_EveryRouteIsClassified walks the real router -- not a
// hand-written list of routes, per the issue's own wording -- and requires
// every pattern it finds to have an entry in routeGroups, the single table
// newRouter itself registers from (router.go).
func TestRouteProperties_EveryRouteIsClassified(t *testing.T) {
	mux := newRouter(testDeps(t))
	if uncovered := unclassifiedRoutes(t, mux); len(uncovered) > 0 {
		t.Errorf("routes with no routeGroups entry: %v", uncovered)
	}
}

// TestRouteProperties_UnregisteredRouteIsCaught is the issue's "Adding a
// route without its layer fails a test -- seen once": a route registered
// directly on the mux, bypassing routeGroup.wrap and routeGroups entirely,
// is exactly the mistake unclassifiedRoutes exists to catch. Proven by
// constructing the violation here, rather than by breaking newRouter itself
// and reverting -- what this demonstrates is "a new route with no group
// entry is caught," not "the production router is currently broken."
func TestRouteProperties_UnregisteredRouteIsCaught(t *testing.T) {
	mux := newRouter(testDeps(t))
	mux.Get("/debug", func(http.ResponseWriter, *http.Request) {}) // no routeGroups entry, no wrap

	uncovered := unclassifiedRoutes(t, mux)
	if len(uncovered) == 0 {
		t.Fatal("expected the unclassified /debug route to be reported; the property check did not catch it")
	}
	found := false
	for _, u := range uncovered {
		if u == "GET /debug" {
			found = true
		}
	}
	if !found {
		t.Errorf("uncovered routes = %v, want it to include \"GET /debug\"", uncovered)
	}
}

func getLogin(t *testing.T, mux *chi.Mux) (token string, cookie *http.Cookie, rec *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/login", http.NoBody)
	req.Host = "usher.test"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == csrf.DefaultCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("GET /login did not set a CSRF cookie")
	}
	body := rec.Body.String()
	const marker = `name="moat.csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("GET /login response did not render the CSRF field: %s", body)
	}
	rest := body[i+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("GET /login response has an unterminated CSRF field value: %s", body)
	}
	token = rest[:end]
	return token, cookie, rec
}

func postLogin(token string, cookie *http.Cookie, identifier, password string) *http.Request {
	form := url.Values{"identifier": {identifier}, "password": {password}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://usher.test/login", strings.NewReader(form.Encode()))
	req.Host = "usher.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://usher.test")
	req.Header.Set(csrf.DefaultHeaderName, token)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

// TestLoginRoute_GoldenPath is the chain's normal case: a correct
// credential, through the full composed chain, rotates the session (#20)
// and renders the logged-in placeholder.
func TestLoginRoute_GoldenPath(t *testing.T) {
	mux := newRouter(testDeps(t))
	token, cookie, _ := getLogin(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLogin(token, cookie, testIdentifier, testPassword))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login with correct credentials = %d, body: %s", rec.Code, rec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Error("a successful login did not set the session cookie")
	}
}

// TestLoginRoute_SecurityHeadersOnEveryResponse is RS-32: every HTML
// response -- success or rejection -- carries frame-ancestors 'none'.
//
// Negative control: with the global
// r.Use(secureheaders.Middleware(...)) line removed from newRouter, this
// test failed -- the header was absent entirely. Verified by hand, restored
// before committing.
func TestLoginRoute_SecurityHeadersOnEveryResponse(t *testing.T) {
	mux := newRouter(testDeps(t))
	_, _, rec := getLogin(t, mux)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP = %q, want it to contain frame-ancestors 'none' (RS-32)", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options missing on GET /login")
	}
}

// TestLoginRoute_InlineScriptNonceMatchesCSP is RS-36's actual claim: the
// one inline script the login page renders runs under moat's per-request
// CSP nonce, not merely that a nonce exists somewhere. A page whose script
// nonce does not match the header's would be silently blocked by the
// browser — the exact "broken page that looks like a CSP misconfiguration"
// secureheaders' own WithNonceErrorHandler doc warns about, just reached
// from the template side instead of a CSPRNG failure.
//
// Negative control: with login.go's render no longer copying
// secureheaders.Nonce(r) into the template data, this test failed — the
// script rendered with nonce="" while the header carried the real value.
// Verified by hand, restored before committing.
//
// Caught flaky in CI (#75): the comparison originally built the expected
// `<script nonce="...">` string from the header's raw nonce value directly,
// but html/template's attribute escaper (stricter than the exported
// html.EscapeString) turns a "+" in a base64 nonce into "&#43;". Passed
// locally and in CI until a run happened to draw a nonce containing one.
// Fixed by extracting the rendered nonce and unescaping it instead of
// escaping the expected value forward — html.UnescapeString reverses any
// valid HTML entity, so it does not need to replicate the unexported
// escaper exactly.
func TestLoginRoute_InlineScriptNonceMatchesCSP(t *testing.T) {
	mux := newRouter(testDeps(t))
	_, _, rec := getLogin(t, mux)

	csp := rec.Header().Get("Content-Security-Policy")
	i := strings.Index(csp, "'nonce-")
	if i < 0 {
		t.Fatalf("CSP has no nonce source: %q", csp)
	}
	rest := csp[i+len("'nonce-"):]
	end := strings.Index(rest, "'")
	if end < 0 {
		t.Fatalf("CSP has an unterminated nonce source: %q", csp)
	}
	headerNonce := rest[:end]

	body := rec.Body.String()
	const marker = `<script nonce="`
	mi := strings.Index(body, marker)
	if mi < 0 {
		t.Fatalf("rendered page has no <script nonce=\"...\"> tag: %s", body)
	}
	rest = body[mi+len(marker):]
	mend := strings.Index(rest, `"`)
	if mend < 0 {
		t.Fatalf("rendered page's script nonce attribute is unterminated: %s", body)
	}
	// html/template's attribute escaper is stricter than the exported
	// html.EscapeString (it also escapes "+", which a base64 nonce can
	// contain, to "&#43;") and is not itself exported, so this compares the
	// other direction: html.UnescapeString correctly reverses any valid
	// HTML entity, including that one, back to the raw nonce the header
	// carries.
	renderedNonce := html.UnescapeString(rest[:mend])
	if renderedNonce != headerNonce {
		t.Errorf("rendered script nonce = %q, want the CSP header's nonce %q", renderedNonce, headerNonce)
	}
}

// TestLoginRoute_NoStore is RS-26, applied per REQUIREMENTS §7.2's table to
// the browser-forms group.
//
// Negative control: with browserForms.noStore changed to false, this test
// failed -- Cache-Control was absent. Verified by hand, restored before
// committing.
func TestLoginRoute_NoStore(t *testing.T) {
	mux := newRouter(testDeps(t))
	_, _, rec := getLogin(t, mux)

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q (RS-26)", got, "no-store")
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want %q", got, "no-cache")
	}
}

// TestLoginRoute_POSTWithoutCSRFTokenIsRejected is RS-12a, and also proves
// RS-32/RS-26 hold on a *rejection*, not just a success: the fixed order
// (chain.go) puts secureheaders and no-store outermost specifically so a
// 403 still carries them.
//
// Negative control: with browserForms.csrf changed to false, this test
// failed -- the request reached the handler and logged in successfully
// (200, not 403) despite carrying no CSRF token at all. Verified by hand,
// restored before committing.
func TestLoginRoute_POSTWithoutCSRFTokenIsRejected(t *testing.T) {
	mux := newRouter(testDeps(t))

	form := url.Values{"identifier": {testIdentifier}, "password": {testPassword}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://usher.test/login", strings.NewReader(form.Encode()))
	req.Host = "usher.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://usher.test")
	// Deliberately no cookie, no token: an attacker forging this POST has
	// neither.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /login with no CSRF cookie/token = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("a CSRF rejection did not carry no-store: Cache-Control = %q", got)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("a CSRF rejection did not carry frame-ancestors 'none'")
	}
}

// TestLoginRoute_WrongPasswordRendersGenericError proves RS-14's message
// symmetry survives through the HTTP layer: the login route does not
// distinguish an unknown identifier from a wrong password in its response.
func TestLoginRoute_WrongPasswordRendersGenericError(t *testing.T) {
	mux := newRouter(testDeps(t))
	token, cookie, _ := getLogin(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLogin(token, cookie, testIdentifier, "wrong password"))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login with a wrong password = %d, want %d (the form re-renders)", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), genericLoginError) {
		t.Errorf("response does not contain the generic error message: %s", rec.Body.String())
	}
}

// TestLoginRoute_EmitsSuccessEvent is #22's first done-when item, the
// success half: a correct login emits an EventLoginAttempt/OutcomeSuccess
// event, asserted via the in-process sink rather than a running crier.
//
// Negative control: with the `h.emit(...)` call removed from login.go's
// success branch, this test failed -- the sink recorded zero events.
// Verified by hand, restored before committing.
func TestLoginRoute_EmitsSuccessEvent(t *testing.T) {
	deps, sink := testDepsWithSink(t)
	mux := newRouter(deps)
	token, cookie, _ := getLogin(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLogin(token, cookie, testIdentifier, testPassword))

	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("sink recorded %d events, want 1: %+v", len(events), events)
	}
	if events[0].Type != audit.EventLoginAttempt || events[0].Outcome != audit.OutcomeSuccess {
		t.Errorf("event = %+v, want {Type: %q, Outcome: %q}", events[0], audit.EventLoginAttempt, audit.OutcomeSuccess)
	}
	if events[0].Subject != testIdentifier {
		t.Errorf("event.Subject = %q, want %q", events[0].Subject, testIdentifier)
	}
}

// TestLoginRoute_EmitsFailureEvent is the same done-when item's failure
// half.
//
// Negative control: with the `h.emit(...)` call removed from login.go's
// ErrLoginFailed branch, this test failed -- the sink recorded zero
// events. Verified by hand, restored before committing.
func TestLoginRoute_EmitsFailureEvent(t *testing.T) {
	deps, sink := testDepsWithSink(t)
	mux := newRouter(deps)
	token, cookie, _ := getLogin(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLogin(token, cookie, testIdentifier, "wrong password"))

	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("sink recorded %d events, want 1: %+v", len(events), events)
	}
	if events[0].Type != audit.EventLoginAttempt || events[0].Outcome != audit.OutcomeFailure {
		t.Errorf("event = %+v, want {Type: %q, Outcome: %q}", events[0], audit.EventLoginAttempt, audit.OutcomeFailure)
	}
}

// TestLoginRoute_EmitsRateLimitedEvent is the done-when item's third case:
// a rejection from the account axis (RS-22, inside identity.Authenticator)
// emits EventRateLimited, distinct from an ordinary login failure.
//
// Negative control: with the `h.emit(...)` call removed from login.go's
// ErrRateLimited branch, this test failed -- the sink recorded zero
// events. Verified by hand, restored before committing.
func TestLoginRoute_EmitsRateLimitedEvent(t *testing.T) {
	deps, sink := testDepsWithSink(t)

	hasher, err := identity.NewHasher(4, time.Second, weakParams, 1<<30)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	// burst=1, perSecond=0: the bucket never refills, so the second Allow
	// call -- here, the second login attempt for the same identifier -- is
	// always denied, deterministically.
	limiter := ratelimit.New(1, 0)
	auth, err := identity.NewAuthenticator(newFakeUserStore(t), hasher, weakParams,
		identity.WithAccountLimiter(limiter))
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	deps.Authenticator = auth

	mux := newRouter(deps)
	token, cookie, _ := getLogin(t, mux)

	// First attempt consumes the account axis's one-request burst --
	// correct credentials, so it also emits a success event this test
	// does not care about.
	mux.ServeHTTP(httptest.NewRecorder(), postLogin(token, cookie, testIdentifier, testPassword))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLogin(token, cookie, testIdentifier, testPassword))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt = %d, want %d (rate limited)", rec.Code, http.StatusTooManyRequests)
	}

	var rateLimited []audit.Event
	for _, e := range sink.Events() {
		if e.Type == audit.EventRateLimited {
			rateLimited = append(rateLimited, e)
		}
	}
	if len(rateLimited) != 1 {
		t.Fatalf("sink recorded %d EventRateLimited events, want 1: %+v", len(rateLimited), sink.Events())
	}
	if rateLimited[0].Outcome != audit.OutcomeFailure {
		t.Errorf("EventRateLimited outcome = %q, want %q", rateLimited[0].Outcome, audit.OutcomeFailure)
	}
}

// seedPendingChallenge saves a Challenge directly into deps.Challenges
// with no Subject -- "a client reached /authorize, but login has not
// happened yet" -- the state /login's own GET handler must decide what
// to do about (ADR-0020). prompt and maxAge are the two fields this
// decision depends on; every other field mirrors seedChallenge
// (consent_test.go) so assertErrorRedirect's own hardcoded expectations
// (state "xyz123") keep working unchanged.
func seedPendingChallenge(t *testing.T, deps routerDeps, id, clientID, prompt string, maxAge *time.Duration) session.Challenge {
	t.Helper()
	c := session.Challenge{
		ID:            id,
		ClientID:      clientID,
		RedirectURI:   testRedirectURI,
		Scope:         []string{"openid"},
		State:         "xyz123",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		Prompt:        prompt,
		MaxAge:        maxAge,
		ExpiresAt:     deps.Now().Add(5 * time.Minute),
	}
	if err := deps.Challenges.Save(context.Background(), c); err != nil {
		t.Fatalf("seed pending challenge: %v", err)
	}
	return c
}

// seedSession saves a BrowserSession directly into deps.Sessions,
// simulating "this browser already has a live AS session" without going
// through a real login. rawID is both the fake store's key and the
// value sessionCookie attaches to a request -- the fake, unlike the real
// Redis store, does not hash it (router_test.go's own fakeSessionStore),
// which is exactly what makes this useful as a test double for
// SessionStore.Get(rawID).
func seedSession(t *testing.T, deps routerDeps, rawID, subject string, authTime time.Time) {
	t.Helper()
	sess := session.BrowserSession{
		ID: rawID, Subject: subject, AuthTime: authTime,
		IdleUntil: deps.Now().Add(time.Hour), ExpiresAt: deps.Now().Add(24 * time.Hour),
	}
	if err := deps.Sessions.Save(context.Background(), sess); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func sessionCookie(rawID string) *http.Cookie {
	// #nosec G124 -- this is a cookie attached to an outgoing *test
	// request*, simulating what a browser already holding usher's
	// session cookie would send back; Secure/HttpOnly/SameSite are
	// response-only attributes (NewSessionCookie, internal/session
	// /cookie.go, is what sets them on the real Set-Cookie) and have no
	// meaning on a cookie a request carries.
	return &http.Cookie{Name: session.CookieName, Value: rawID}
}

// getLoginRequest builds a raw GET /login request, optionally carrying a
// login_challenge and any cookies -- unlike getLogin, it does not expect
// a rendered form (several of the tests below expect a redirect
// instead), so it does not try to extract a CSRF token.
func getLoginRequest(challengeID string, cookies ...*http.Cookie) *http.Request {
	target := "https://usher.test/login"
	if challengeID != "" {
		target += "?login_challenge=" + url.QueryEscape(challengeID)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	req.Host = "usher.test"
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// TestLoginRoute_PromptNoneNoSessionGetsLoginRequired is RF-11's own
// first done-when (ADR-0020): prompt=none with no existing session at
// all is refused with login_required, redirected to the client -- never
// the login form prompt=none exists specifically to suppress.
//
// Negative control: with the `challenge.Prompt == "none"` check removed
// from login.go's get, this test failed -- the form rendered (status
// 200) instead of redirecting. Verified by hand, restored before
// committing.
func TestLoginRoute_PromptNoneNoSessionGetsLoginRequired(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "none", nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getLoginRequest(c.ID))

	assertErrorRedirect(t, rec, "login_required")
}

// TestLoginRoute_PromptNoneValidSessionProceedsSilently is the success
// half of the same done-when: a session that already satisfies the
// request (no prompt=login, no exceeded max_age) skips the form entirely
// and hands straight off to /consent, carrying the session's own subject
// and auth_time onto the challenge.
//
// Negative control: with needsFreshAuthentication changed to
// unconditionally return true, this test failed -- the response was 200
// (the rendered form) instead of a redirect to /consent. Verified by
// hand, restored before committing.
func TestLoginRoute_PromptNoneValidSessionProceedsSilently(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "none", nil)
	authTime := deps.Now().Add(-10 * time.Minute)
	seedSession(t, deps, "raw-session-1", testIdentifier, authTime)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getLoginRequest(c.ID, sessionCookie("raw-session-1")))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d (redirect to /consent), body: %s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path != "/consent" {
		t.Errorf("Location path = %q, want /consent", loc.Path)
	}

	got, err := deps.Challenges.Get(context.Background(), c.ID)
	if err != nil {
		t.Fatalf("Get challenge: %v", err)
	}
	if got.Subject != testIdentifier {
		t.Errorf("challenge Subject = %q, want %q", got.Subject, testIdentifier)
	}
	if !got.AuthTime.Equal(authTime) {
		t.Errorf("challenge AuthTime = %s, want the session's own %s, not a fresh one", got.AuthTime, authTime)
	}
}

// TestLoginRoute_PromptLoginForcesFormEvenWithValidSession is RF-11's
// second done-when: prompt=login forces re-authentication regardless of
// an otherwise perfectly valid, unexpired session.
//
// Negative control: with the `challenge.Prompt == "login"` branch
// removed from needsFreshAuthentication, this test failed -- the
// response redirected straight to /consent instead of rendering the
// form. Verified by hand, restored before committing.
func TestLoginRoute_PromptLoginForcesFormEvenWithValidSession(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "login", nil)
	seedSession(t, deps, "raw-session-1", testIdentifier, deps.Now().Add(-time.Minute))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getLoginRequest(c.ID, sessionCookie("raw-session-1")))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (the login form), body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `name="moat.csrf"`) {
		t.Error("prompt=login did not render the login form despite a valid session")
	}
}

// TestLoginRoute_MaxAgeExceededForcesForm is RF-11's max_age done-when,
// the exceeded half: a session whose AuthTime is older than max_age
// allows is treated exactly like no session at all.
//
// Negative control: with the `challenge.MaxAge != nil && ...` branch
// removed from needsFreshAuthentication, this test failed -- the
// response redirected to /consent despite the session being well past
// the requested max_age. Verified by hand, restored before committing.
func TestLoginRoute_MaxAgeExceededForcesForm(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	maxAge := 30 * time.Second
	c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "", &maxAge)
	seedSession(t, deps, "raw-session-1", testIdentifier, deps.Now().Add(-time.Hour))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getLoginRequest(c.ID, sessionCookie("raw-session-1")))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (the login form), body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `name="moat.csrf"`) {
		t.Error("an exceeded max_age did not render the login form")
	}
}

// TestLoginRoute_MaxAgeSatisfiedProceedsSilently is the same check's
// other side: a session authenticated well within the requested max_age
// is accepted, silently.
func TestLoginRoute_MaxAgeSatisfiedProceedsSilently(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	maxAge := time.Hour
	c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "", &maxAge)
	seedSession(t, deps, "raw-session-1", testIdentifier, deps.Now().Add(-time.Minute))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getLoginRequest(c.ID, sessionCookie("raw-session-1")))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d (redirect to /consent), body: %s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
}

// TestLoginRoute_NoPromptNoSessionRendersForm is the control case every
// test above is a variation of: with neither prompt nor max_age in play
// and no session at all, GET /login renders the form exactly as it did
// before #47 -- this issue changes what happens when a session or a
// prompt/max_age value is present, never the plain case.
func TestLoginRoute_NoPromptNoSessionRendersForm(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "", nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getLoginRequest(c.ID))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (the login form), body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
