package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/session"
)

// fakeConsentStore is a small, controllable stand-in for oauth.ConsentStore.
// Proven-elsewhere business logic (internal/store/postgres's own real
// integration tests); a fake is the right tool for testing the /consent
// handler's own logic over the interface.
type fakeConsentStore struct {
	grants map[string][]string
}

func newFakeConsentStore() *fakeConsentStore {
	return &fakeConsentStore{grants: map[string][]string{}}
}

func consentKey(subject, clientID string) string { return subject + "|" + clientID }

func (f *fakeConsentStore) Granted(_ context.Context, subject, clientID string) (scope []string, ok bool, err error) {
	scope, ok = f.grants[consentKey(subject, clientID)]
	return scope, ok, nil
}

func (f *fakeConsentStore) Grant(_ context.Context, subject, clientID string, scope []string) error {
	f.grants[consentKey(subject, clientID)] = scope
	return nil
}

func (f *fakeConsentStore) Revoke(_ context.Context, subject, clientID string) error {
	delete(f.grants, consentKey(subject, clientID))
	return nil
}

const testSubject = "alice@example.com"

// seedChallenge saves a Challenge directly into deps.Challenges with
// Subject already set, simulating "login already happened for this
// challenge" without going through /authorize or /login.
func seedChallenge(t *testing.T, deps routerDeps, id, clientID string, scope []string) session.Challenge {
	t.Helper()
	c := session.Challenge{
		ID:            id,
		ClientID:      clientID,
		RedirectURI:   testRedirectURI,
		Scope:         scope,
		State:         "xyz123",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		Subject:       testSubject,
		ExpiresAt:     deps.Now().Add(5 * time.Minute),
	}
	if err := deps.Challenges.Save(context.Background(), c); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	return c
}

func getConsent(t *testing.T, mux http.Handler, challengeID string) (token string, cookie *http.Cookie, rec *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://usher.test/consent?login_challenge="+url.QueryEscape(challengeID), http.NoBody)
	req.Host = "usher.test"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == csrf.DefaultCookieName {
			cookie = c
		}
	}
	body := rec.Body.String()
	const marker = `name="moat.csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		return "", cookie, rec // no form rendered (e.g. skipped straight to the granted page)
	}
	rest := body[i+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("GET /consent response has an unterminated CSRF field value: %s", body)
	}
	return rest[:end], cookie, rec
}

func postConsent(token string, cookie *http.Cookie, challengeID, decision string) *http.Request {
	form := url.Values{"login_challenge": {challengeID}, "decision": {decision}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://usher.test/consent", strings.NewReader(form.Encode()))
	req.Host = "usher.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://usher.test")
	req.Header.Set(csrf.DefaultHeaderName, token)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

func consentDeps(t *testing.T, clients ...identity.Client) routerDeps {
	t.Helper()
	deps := testDeps(t)
	deps.Clients = clients
	return deps
}

func consentTestClient() identity.Client {
	c := testClient()
	c.RequireConsent = true
	return c
}

// TestConsent_NoPriorGrantRendersForm is the control case: a fresh
// challenge with no recorded consent renders the form rather than
// skipping it.
func TestConsent_NoPriorGrantRendersForm(t *testing.T) {
	deps := consentDeps(t, consentTestClient())
	mux := newRouter(deps)
	c := seedChallenge(t, deps, "challenge-1", testClientID, []string{"openid"})

	token, _, rec := getConsent(t, mux, c.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /consent with no prior grant = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if token == "" {
		t.Fatal("no CSRF token rendered -- the consent form did not render")
	}
	if !strings.Contains(rec.Body.String(), "openid") {
		t.Errorf("rendered form does not mention the requested scope: %s", rec.Body.String())
	}
}

// TestConsent_PriorGrantCoveringScopeSkipsForm confirms the other half:
// once consent already covers the requested scope, the form is skipped.
func TestConsent_PriorGrantCoveringScopeSkipsForm(t *testing.T) {
	deps := consentDeps(t, consentTestClient())
	if err := deps.Consents.Grant(context.Background(), testSubject, testClientID, []string{"openid", "profile"}); err != nil {
		t.Fatalf("seed prior grant: %v", err)
	}
	mux := newRouter(deps)
	c := seedChallenge(t, deps, "challenge-1", testClientID, []string{"openid"})

	_, _, rec := getConsent(t, mux, c.ID)
	if strings.Contains(rec.Body.String(), `name="moat.csrf"`) {
		t.Errorf("the consent form rendered despite a prior grant covering the requested scope: %s", rec.Body.String())
	}
}

// TestConsent_SupersetOfGrantedScopeShowsFormAgain is the issue's own
// done-when: requesting a scope that goes beyond a prior grant re-prompts,
// rather than silently widening access.
//
// Negative control: with the `scopeSubset` check in serve replaced with
// `ok` alone (any prior grant, regardless of its scope, counts as
// covering), this test failed -- the form was skipped even though the
// request asked for a scope ("profile") the prior grant never covered.
// Verified by hand, restored before committing.
func TestConsent_SupersetOfGrantedScopeShowsFormAgain(t *testing.T) {
	deps := consentDeps(t, consentTestClient())
	if err := deps.Consents.Grant(context.Background(), testSubject, testClientID, []string{"openid"}); err != nil {
		t.Fatalf("seed prior grant: %v", err)
	}
	mux := newRouter(deps)
	c := seedChallenge(t, deps, "challenge-1", testClientID, []string{"openid", "profile"})

	token, _, rec := getConsent(t, mux, c.ID)
	if rec.Code != http.StatusOK || token == "" {
		t.Fatalf("GET /consent requesting a superset of the prior grant did not render the form (status=%d): %s", rec.Code, rec.Body.String())
	}
}

func TestConsent_AllowGrantsUnionAndCompletes(t *testing.T) {
	deps := consentDeps(t, consentTestClient())
	if err := deps.Consents.Grant(context.Background(), testSubject, testClientID, []string{"openid"}); err != nil {
		t.Fatalf("seed prior grant: %v", err)
	}
	mux := newRouter(deps)
	c := seedChallenge(t, deps, "challenge-1", testClientID, []string{"openid", "profile"})

	token, cookie, _ := getConsent(t, mux, c.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postConsent(token, cookie, c.ID, "allow"))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /consent decision=allow = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	granted, ok, err := deps.Consents.Granted(context.Background(), testSubject, testClientID)
	if err != nil || !ok {
		t.Fatalf("Granted after allow: ok=%v, err=%v", ok, err)
	}
	if !scopeSubset([]string{"openid", "profile"}, granted) || !scopeSubset(granted, []string{"openid", "profile"}) {
		t.Errorf("granted scope after allow = %v, want exactly [openid profile]", granted)
	}
}

// TestConsent_DenyRedirectsWithAccessDenied confirms the deny path reuses
// the shared RFC 6749 error-redirect helper, including iss.
func TestConsent_DenyRedirectsWithAccessDenied(t *testing.T) {
	deps := consentDeps(t, consentTestClient())
	mux := newRouter(deps)
	c := seedChallenge(t, deps, "challenge-1", testClientID, []string{"openid"})

	token, cookie, _ := getConsent(t, mux, c.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postConsent(token, cookie, c.ID, "deny"))

	if rec.Code != http.StatusFound {
		t.Fatalf("POST /consent decision=deny = %d, want %d", rec.Code, http.StatusFound)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Errorf("error = %q, want access_denied", got)
	}
	if got := loc.Query().Get("iss"); got == "" {
		t.Error("deny redirect carries no iss")
	}
	if got := loc.Query().Get("state"); got != "xyz123" {
		t.Errorf("state = %q, want the challenge's original state echoed", got)
	}
}

// TestConsent_NoSubjectRedirectsToLogin confirms a challenge nobody has
// authenticated against yet sends the browser to /login first.
func TestConsent_NoSubjectRedirectsToLogin(t *testing.T) {
	deps := consentDeps(t, consentTestClient())
	mux := newRouter(deps)
	c := session.Challenge{
		ID: "challenge-1", ClientID: testClientID, RedirectURI: testRedirectURI,
		Scope: []string{"openid"}, State: "xyz123",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		ExpiresAt:     deps.Now().Add(5 * time.Minute),
		// Subject deliberately left "" -- login has not happened.
	}
	if err := deps.Challenges.Save(context.Background(), c); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://usher.test/consent?login_challenge="+c.ID, http.NoBody)
	req.Host = "usher.test"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET /consent with no Subject = %d, want %d (redirect to /login)", rec.Code, http.StatusSeeOther)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/login" {
		t.Errorf("Location path = %q, want /login", loc.Path)
	}
}

// TestConsent_RequireConsentFalseSkipsForm confirms RF-01's own
// RequireConsent flag: a client configured not to require consent skips
// the form even with no prior grant at all.
func TestConsent_RequireConsentFalseSkipsForm(t *testing.T) {
	client := testClient()
	client.RequireConsent = false
	deps := consentDeps(t, client)
	mux := newRouter(deps)
	c := seedChallenge(t, deps, "challenge-1", testClientID, []string{"openid"})

	_, _, rec := getConsent(t, mux, c.ID)
	if strings.Contains(rec.Body.String(), `name="moat.csrf"`) {
		t.Errorf("the consent form rendered for a RequireConsent=false client: %s", rec.Body.String())
	}
}

// TestConsent_ScopeRenderedEscaped is the issue's second done-when (RS-36,
// T-20/T-21): a requested scope value is rendered through html/template's
// default escaping, never raw.
//
// Negative control: with consentPageData given a parallel UnsafeScope
// []template.HTML field, renderConsentForm populated from the same
// requested scope strings, and the template's range switched to it, this
// test failed -- the rendered page contained the literal, unescaped
// "<script>alert(1)</script>" tag. In the real file this exact change is
// what the project's existing forbidigo rule for template.HTML refuses to
// let compile-and-pass-lint in the first place (RS-36); this test is the
// runtime half of that guarantee. Verified by hand, restored before
// committing.
func TestConsent_ScopeRenderedEscaped(t *testing.T) {
	deps := consentDeps(t, consentTestClient())
	mux := newRouter(deps)
	c := seedChallenge(t, deps, "challenge-1", testClientID, []string{`<script>alert(1)</script>`})

	_, _, rec := getConsent(t, mux, c.ID)
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("the requested scope rendered unescaped: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected the scope to render HTML-escaped, got: %s", body)
	}
}
