package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/usher/internal/session"
)

func getLogout(t *testing.T, mux http.Handler) (token string, cookie *http.Cookie, rec *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/logout", http.NoBody)
	req.Host = "usher.test"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == csrf.DefaultCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("GET /logout did not set a CSRF cookie")
	}
	body := rec.Body.String()
	const marker = `name="moat.csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("GET /logout response did not render the CSRF field: %s", body)
	}
	rest := body[i+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("GET /logout response has an unterminated CSRF field value: %s", body)
	}
	return rest[:end], cookie, rec
}

func postLogout(token string, csrfCookie, sessCookie *http.Cookie) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://usher.test/logout", http.NoBody)
	req.Host = "usher.test"
	req.Header.Set("Origin", "https://usher.test")
	req.Header.Set(csrf.DefaultHeaderName, token)
	if csrfCookie != nil {
		req.AddCookie(csrfCookie)
	}
	if sessCookie != nil {
		req.AddCookie(sessCookie)
	}
	return req
}

// TestLogoutRoute_GoldenPath is RS-31 itself: a real, live session is
// gone from the server-side store once POST /logout responds -- not
// merely a cleared cookie the browser could ignore.
//
// Negative control: with the `h.sessions.Delete` call removed from
// logout.go's post, this test failed -- deps.Sessions.Get still found
// the session after POST /logout responded 200. Verified by hand,
// restored before committing.
func TestLogoutRoute_GoldenPath(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	seedSession(t, deps, "raw-session-1", testIdentifier, deps.Now())

	token, csrfCookie, _ := getLogout(t, mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLogout(token, csrfCookie, sessionCookie("raw-session-1")))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /logout = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Logged out") {
		t.Errorf("response does not confirm logout: %s", rec.Body.String())
	}

	if _, err := deps.Sessions.Get(context.Background(), "raw-session-1"); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("session lookup after logout = %v, want %v -- the server-side session must be gone", err, session.ErrSessionNotFound)
	}
}

// TestLogoutRoute_NoSessionIsIdempotent mirrors revoke.go's own RFC 7009
// ambiguity: logging out with no session cookie at all still succeeds.
func TestLogoutRoute_NoSessionIsIdempotent(t *testing.T) {
	mux := newRouter(testDeps(t))
	token, csrfCookie, _ := getLogout(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLogout(token, csrfCookie, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /logout with no session = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestLogoutRoute_ClearsSessionCookie is RS-31's own browser-side half:
// the response clears the session cookie (MaxAge=-1), so a browser that
// ignores Clear-Site-Data entirely still stops sending it.
func TestLogoutRoute_ClearsSessionCookie(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	seedSession(t, deps, "raw-session-1", testIdentifier, deps.Now())

	token, csrfCookie, _ := getLogout(t, mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLogout(token, csrfCookie, sessionCookie("raw-session-1")))

	var cleared *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatal("POST /logout did not set a session cookie at all")
	}
	if cleared.MaxAge >= 0 {
		t.Errorf("session cookie MaxAge = %d, want negative (deleted)", cleared.MaxAge)
	}
}

// TestLogoutRoute_ClearSiteDataOmitsCookies is ADR-0021's own done-when:
// the header names cache and storage, never cookies -- usher's own
// __Host- session cookie is already cleared directly (the test above),
// and RS-27's registrable-domain caveat is exactly what ADR-0021 decided
// not to reach for.
//
// Negative control: with the clearSiteData call in router.go changed to
// also pass secureheaders.SiteDataCookies, this test failed -- the
// header value included "cookies". Verified by hand, restored before
// committing.
func TestLogoutRoute_ClearSiteDataOmitsCookies(t *testing.T) {
	mux := newRouter(testDeps(t))
	token, csrfCookie, _ := getLogout(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLogout(token, csrfCookie, nil))

	got := rec.Header().Get("Clear-Site-Data")
	want := `"cache", "storage"`
	if got != want {
		t.Errorf("Clear-Site-Data = %q, want %q", got, want)
	}
}

// TestLogoutRoute_ClearSiteDataNotOnGET confirms moat's own documented
// placement: the header belongs on the response that actually logs out,
// not the confirmation form a GET renders before anything has happened.
func TestLogoutRoute_ClearSiteDataNotOnGET(t *testing.T) {
	mux := newRouter(testDeps(t))
	_, _, rec := getLogout(t, mux)

	if got := rec.Header().Get("Clear-Site-Data"); got != "" {
		t.Errorf("GET /logout carries Clear-Site-Data = %q, want none (it belongs on the POST)", got)
	}
}

// TestLogoutRoute_NoStore mirrors TestLoginRoute_NoStore: /logout is in
// the same browserForms group (RS-26).
func TestLogoutRoute_NoStore(t *testing.T) {
	mux := newRouter(testDeps(t))
	_, _, rec := getLogout(t, mux)

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q (RS-26)", got, "no-store")
	}
}

// TestLogoutRoute_POSTWithoutCSRFTokenIsRejected mirrors
// TestLoginRoute_POSTWithoutCSRFTokenIsRejected: an attacker forging
// this POST has neither the CSRF cookie nor the token.
func TestLogoutRoute_POSTWithoutCSRFTokenIsRejected(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	seedSession(t, deps, "raw-session-1", testIdentifier, deps.Now())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://usher.test/logout", http.NoBody)
	req.Host = "usher.test"
	req.Header.Set("Origin", "https://usher.test")
	req.AddCookie(sessionCookie("raw-session-1"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /logout with no CSRF cookie/token = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if _, err := deps.Sessions.Get(context.Background(), "raw-session-1"); err != nil {
		t.Errorf("a CSRF-rejected logout deleted the session anyway: Get = %v", err)
	}
}

// TestLogoutRoute_OldSessionCookieRefusedAfterLogout is the issue's own
// second done-when, proven independently of Clear-Site-Data and of the
// cleared Set-Cookie: replaying the exact same session cookie value
// after logout, against a flow that depends on it (#47's own silent
// reuse at /login), is refused purely because the server-side session
// is gone.
func TestLogoutRoute_OldSessionCookieRefusedAfterLogout(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	seedSession(t, deps, "raw-session-1", testIdentifier, deps.Now())

	token, csrfCookie, _ := getLogout(t, mux)
	logoutRec := httptest.NewRecorder()
	mux.ServeHTTP(logoutRec, postLogout(token, csrfCookie, sessionCookie("raw-session-1")))
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("POST /logout = %d, want %d", logoutRec.Code, http.StatusOK)
	}

	c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "", nil)
	rec := httptest.NewRecorder()
	// Deliberately the OLD raw session id -- never reissued, never
	// refreshed -- the exact value POST /logout above already deleted
	// server-side.
	mux.ServeHTTP(rec, getLoginRequest(c.ID, sessionCookie("raw-session-1")))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (the login form -- the old session must not grant silent reuse), body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `name="moat.csrf"`) {
		t.Error("the old session cookie silently completed login instead of being refused")
	}
}
