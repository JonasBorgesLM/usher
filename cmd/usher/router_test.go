package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/usher/internal/identity"
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

func (f *fakeChallengeStore) SetSubject(_ context.Context, id, subject string) error {
	c, ok := f.challenges[id]
	if !ok {
		return session.ErrChallengeNotFound
	}
	c.Subject = subject
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
		SessionIdleTTL:     time.Hour,
		SessionAbsoluteTTL: 24 * time.Hour,
		Now:                func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
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
	wantScript := `<script nonce="` + headerNonce + `">`
	if !strings.Contains(body, wantScript) {
		t.Errorf("rendered page does not contain %q; body: %s", wantScript, body)
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
