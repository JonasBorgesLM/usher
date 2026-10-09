package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/internal/session"
)

var errStoreDown = errors.New("store unavailable")

// The wrappers below embed a working fake and fail one method on demand.
// Each failure is switched on only after the GET that renders the form,
// so the POST under test is the one that meets the outage.

type failingConsents struct {
	oauth.ConsentStore
	grantedErr, grantErr error
}

func (f *failingConsents) Granted(ctx context.Context, subject, clientID string) (scope []string, ok bool, err error) {
	if f.grantedErr != nil {
		return nil, false, f.grantedErr
	}
	return f.ConsentStore.Granted(ctx, subject, clientID)
}

func (f *failingConsents) Grant(ctx context.Context, subject, clientID string, scope []string) error {
	if f.grantErr != nil {
		return f.grantErr
	}
	return f.ConsentStore.Grant(ctx, subject, clientID, scope)
}

type failingChallenges struct {
	session.ChallengeStore
	consumeErr, setAuthErr error
}

func (f *failingChallenges) Consume(ctx context.Context, id string) (session.Challenge, error) {
	if f.consumeErr != nil {
		return session.Challenge{}, f.consumeErr
	}
	return f.ChallengeStore.Consume(ctx, id)
}

func (f *failingChallenges) SetAuthenticated(ctx context.Context, id, subject string, authTime time.Time) error {
	if f.setAuthErr != nil {
		return f.setAuthErr
	}
	return f.ChallengeStore.SetAuthenticated(ctx, id, subject, authTime)
}

type failingCodes struct {
	*fakeCodeStore
	saveErr error
}

func (f *failingCodes) Save(ctx context.Context, c oauth.Code) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	return f.fakeCodeStore.Save(ctx, c)
}

type failingSessions struct {
	session.SessionStore
	saveErr error
}

func (f *failingSessions) Save(ctx context.Context, s session.BrowserSession) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	return f.SessionStore.Save(ctx, s)
}

// assertNoCodeIssued fails if rec redirected anywhere carrying a code, or
// if any code reached the store.
func assertNoCodeIssued(t *testing.T, rec *httptest.ResponseRecorder, codes *fakeCodeStore) {
	t.Helper()
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "code=") {
		t.Errorf("response redirected with a code: %s", loc)
	}
	if len(codes.codes) != 0 {
		t.Errorf("%d code(s) reached the CodeStore, want none", len(codes.codes))
	}
}

// TestConsent_PostWithoutLoginRedirectsToLogin: a POST /consent for a
// challenge nobody has authenticated against must not grant consent or
// mint a code — the GET guard alone does not protect the POST, since a
// form can be posted without ever being fetched.
//
// Negative control: with the `challenge.Subject == ""` check removed from
// consent.go's post, this test failed — the POST answered 302, the
// redirect back to the client that carries a code, instead of 303 to
// /login. Verified by hand, restored before committing.
func TestConsent_PostWithoutLoginRedirectsToLogin(t *testing.T) {
	deps := consentDeps(t, consentTestClient())
	mux := newRouter(deps)

	// A CSRF token and cookie are per browser, not per challenge: fetch
	// them from a legitimate challenge's form, then post a different one.
	authed := seedChallenge(t, deps, "challenge-authed", testClientID, []string{"openid"})
	token, cookie, _ := getConsent(t, mux, authed.ID)
	if token == "" {
		t.Fatal("GET /consent rendered no form to take a CSRF token from")
	}

	unauthed := session.Challenge{
		ID: "challenge-unauthed", ClientID: testClientID, RedirectURI: testRedirectURI,
		Scope: []string{"openid"}, State: "xyz123",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		ExpiresAt:     deps.Now().Add(5 * time.Minute),
	}
	if err := deps.Challenges.Save(context.Background(), unauthed); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postConsent(token, cookie, unauthed.ID, "allow"))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /consent with no Subject = %d, want %d (redirect to /login), body: %s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path != "/login" || loc.Query().Get("login_challenge") != unauthed.ID {
		t.Errorf("Location = %q, want /login carrying this challenge", loc.String())
	}
	codes, ok := deps.Codes.(*fakeCodeStore)
	if !ok {
		t.Fatalf("deps.Codes is a %T, want *fakeCodeStore", deps.Codes)
	}
	assertNoCodeIssued(t, rec, codes)
	if _, granted, _ := deps.Consents.Granted(context.Background(), "", testClientID); granted {
		t.Error("consent was recorded for an empty subject")
	}
}

// TestConsent_StoreFailureNeverIssuesCode is RNF-04 on the consent POST:
// whichever store fails, the response is an error and no code exists.
// The control first proves the same flow issues a code when nothing
// fails, so a passing failure case cannot be a flow that never ran.
//
// Negative control: with the `return` removed after each failing call in
// consent.go (Granted, Grant, Consume, code Save), the matching case
// failed — the POST went on to redirect with a code (for Save, a code
// that was never stored; for Consume, to an empty redirect_uri, since the
// failed Consume returned a zero challenge). Verified by hand per case,
// restored before committing.
func TestConsent_StoreFailureNeverIssuesCode(t *testing.T) {
	cases := []struct {
		name string
		fail func(*failingConsents, *failingChallenges, *failingCodes)
	}{
		{"control: nothing fails", func(*failingConsents, *failingChallenges, *failingCodes) {}},
		{"Granted fails", func(c *failingConsents, _ *failingChallenges, _ *failingCodes) { c.grantedErr = errStoreDown }},
		{"Grant fails", func(c *failingConsents, _ *failingChallenges, _ *failingCodes) { c.grantErr = errStoreDown }},
		{"challenge Consume fails", func(_ *failingConsents, ch *failingChallenges, _ *failingCodes) { ch.consumeErr = errStoreDown }},
		{"code Save fails", func(_ *failingConsents, _ *failingChallenges, co *failingCodes) { co.saveErr = errStoreDown }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := consentDeps(t, consentTestClient())
			consents := &failingConsents{ConsentStore: deps.Consents}
			challenges := &failingChallenges{ChallengeStore: deps.Challenges}
			inner := newFakeCodeStore()
			codes := &failingCodes{fakeCodeStore: inner}
			deps.Consents, deps.Challenges, deps.Codes = consents, challenges, codes
			mux := newRouter(deps)

			c := seedChallenge(t, deps, "challenge-1", testClientID, []string{"openid"})
			token, cookie, _ := getConsent(t, mux, c.ID)
			if token == "" {
				t.Fatal("GET /consent rendered no form to take a CSRF token from")
			}

			tc.fail(consents, challenges, codes)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, postConsent(token, cookie, c.ID, "allow"))

			if tc.name == "control: nothing fails" {
				if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "code=") {
					t.Fatalf("control: POST /consent = %d, Location %q, want 302 carrying a code", rec.Code, rec.Header().Get("Location"))
				}
				return
			}
			if rec.Code < 400 {
				t.Errorf("POST /consent = %d, want an error status", rec.Code)
			}
			assertNoCodeIssued(t, rec, inner)
		})
	}
}

// postLoginWithChallenge is postLogin plus the login_challenge field that
// ties the credential to a pending authorization request.
func postLoginWithChallenge(token string, cookie *http.Cookie, challengeID, identifier, password string) *http.Request {
	form := url.Values{"login_challenge": {challengeID}, "identifier": {identifier}, "password": {password}}
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

func sessionCookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName {
			return c
		}
	}
	return nil
}

// TestLogin_PostWithChallengeHandsOffToConsent is the password-login path
// of the authorization flow: a correct credential posted against a pending
// challenge marks the challenge authenticated and hands off to /consent.
// Until this test, only end-to-end runs (README examples, threat probes)
// reached it.
func TestLogin_PostWithChallengeHandsOffToConsent(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "", nil)
	token, cookie, _ := getLogin(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLoginWithChallenge(token, cookie, c.ID, testIdentifier, testPassword))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /login with a challenge = %d, want %d, body: %s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path != "/consent" || loc.Query().Get("login_challenge") != c.ID {
		t.Errorf("Location = %q, want /consent carrying this challenge", loc.String())
	}
	if sessionCookieFrom(rec) == nil {
		t.Error("a successful login did not set the session cookie")
	}
	got, err := deps.Challenges.Get(context.Background(), c.ID)
	if err != nil {
		t.Fatalf("Get challenge: %v", err)
	}
	if got.Subject == "" {
		t.Error("the challenge was not marked authenticated")
	}
	if !got.AuthTime.Equal(deps.Now()) {
		t.Errorf("challenge AuthTime = %s, want the login's own time %s", got.AuthTime, deps.Now())
	}
}

// TestLogin_StoreFailureNeverHandsOff is RNF-04 on the login POST: if the
// new session cannot be saved, or the challenge cannot be marked
// authenticated, the browser gets an error — never a redirect to /consent.
// A failed session save must also never set the session cookie
// (RotateLogin saves before it writes the cookie).
//
// Negative control: with the `return` removed after RotateLogin's error in
// completeLogin, the "session Save fails" case failed — a redirect to
// /consent and the challenge marked authenticated, with no session saved
// behind it; with the `return` removed after SetAuthenticated's error in
// proceedToConsent, the other case failed — a redirect to /consent for a
// challenge that was never marked authenticated. Verified by hand,
// restored before committing.
func TestLogin_StoreFailureNeverHandsOff(t *testing.T) {
	cases := []struct {
		name string
		fail func(*failingSessions, *failingChallenges)
	}{
		{"session Save fails", func(s *failingSessions, _ *failingChallenges) { s.saveErr = errStoreDown }},
		{"challenge SetAuthenticated fails", func(_ *failingSessions, c *failingChallenges) { c.setAuthErr = errStoreDown }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := testDeps(t)
			sessions := &failingSessions{SessionStore: deps.Sessions}
			challenges := &failingChallenges{ChallengeStore: deps.Challenges}
			deps.Sessions, deps.Challenges = sessions, challenges
			mux := newRouter(deps)
			c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "", nil)
			token, cookie, _ := getLogin(t, mux)

			tc.fail(sessions, challenges)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, postLoginWithChallenge(token, cookie, c.ID, testIdentifier, testPassword))

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("POST /login = %d, want %d", rec.Code, http.StatusInternalServerError)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("response redirected to %q, want no hand-off", loc)
			}
			if tc.name == "session Save fails" && sessionCookieFrom(rec) != nil {
				t.Error("a session cookie was set for a session that was never saved")
			}
			got, err := challenges.Get(context.Background(), c.ID)
			if err != nil {
				t.Fatalf("Get challenge: %v", err)
			}
			if got.Subject != "" {
				t.Errorf("challenge Subject = %q, want it left unauthenticated", got.Subject)
			}
		})
	}
}
