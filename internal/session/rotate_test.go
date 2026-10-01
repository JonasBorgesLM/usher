package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JonasBorgesLM/moat/csrf"
)

// fakeSessionStore is a small, controllable stand-in for SessionStore.
// RotateLogin's own logic -- delete-old-then-create-new -- is business
// logic over the interface, already proven against real Redis in #19; a
// fake lets these tests assert the deletion happened and control the new
// session's shape precisely.
type fakeSessionStore struct {
	sessions map[string]BrowserSession
	deleted  []string
}

func newFakeSessionStore(existing ...BrowserSession) *fakeSessionStore {
	m := make(map[string]BrowserSession, len(existing))
	for _, s := range existing {
		m[s.ID] = s
	}
	return &fakeSessionStore{sessions: m}
}

func (f *fakeSessionStore) Save(_ context.Context, s BrowserSession) error {
	f.sessions[s.ID] = s
	return nil
}

func (f *fakeSessionStore) Get(_ context.Context, rawID string) (BrowserSession, error) {
	s, ok := f.sessions[rawID]
	if !ok {
		return BrowserSession{}, ErrSessionNotFound
	}
	return s, nil
}

func (f *fakeSessionStore) Delete(_ context.Context, rawID string) error {
	delete(f.sessions, rawID)
	f.deleted = append(f.deleted, rawID)
	return nil
}

// newTestProtector builds a real csrf.Protector — RS-12b is specifically
// about how this project uses moat's own Rotate, so a fake here would
// prove nothing about the thing the issue is testing.
func newTestProtector(t *testing.T) *csrf.Protector {
	t.Helper()
	secretValue, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatalf("csrf.GenerateSecret: %v", err)
	}
	protector, err := csrf.New(secretValue)
	if err != nil {
		t.Fatalf("csrf.New: %v", err)
	}
	return protector
}

// csrfRequest builds a state-changing (POST) request that satisfies
// Protector.Middleware's Origin check — without a matching Origin or
// Referer, every POST is rejected regardless of token validity, which
// would make these tests unable to distinguish "rejected for a stale
// token" from "rejected because no Origin header was set." It carries no
// token header, so it is only for tests that call RotateLogin directly
// (bypassing Middleware's own gate) rather than through
// protector.Middleware.
func csrfRequest(cookie *http.Cookie) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://usher.test/login", http.NoBody)
	r.Host = "usher.test"
	r.Header.Set("Origin", "https://usher.test")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

// validCSRFRequest is csrfRequest plus the matching token header, so it
// also clears protector.Middleware's own admission check and reaches a
// handler wrapped by it.
func validCSRFRequest(token string, cookie *http.Cookie) *http.Request {
	r := csrfRequest(cookie)
	r.Header.Set(csrf.DefaultHeaderName, token)
	return r
}

// obtainToken drives one GET through protector.Middleware to mint a fresh
// CSRF cookie and token — the way a real login page would, before the
// POST that logs in.
func obtainToken(t *testing.T, protector *csrf.Protector) (token string, cookie *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/login", http.NoBody)
	r.Host = "usher.test"

	protector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := csrf.Token(r)
		if !ok {
			t.Fatal("csrf.Token: no token on a GET through Middleware")
		}
		token = tok
	})).ServeHTTP(rec, r)

	for _, c := range rec.Result().Cookies() {
		if c.Name == csrf.DefaultCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("Middleware did not set a CSRF cookie")
	}
	return token, cookie
}

// TestRotateLogin_SessionIDChanges is the issue's first test: the session
// id before login differs from the one after.
//
// Negative control: with RotateLogin changed to reuse oldRawID instead of
// calling NewRawID, this test failed — the "before" and "after" ids were
// identical. Verified by hand, restored before committing.
func TestRotateLogin_SessionIDChanges(t *testing.T) {
	store := newFakeSessionStore(BrowserSession{ID: "pre-login-id", Subject: ""})
	protector := newTestProtector(t)
	_, cookie := obtainToken(t, protector)

	rec := httptest.NewRecorder()
	r := csrfRequest(cookie)

	sess, err := RotateLogin(r.Context(), rec, r, protector, store,
		"pre-login-id", "alice@example.com", time.Now(), time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("RotateLogin: %v", err)
	}
	if sess.ID == "pre-login-id" {
		t.Error("session id after login equals the id before login")
	}
	if _, err := store.Get(context.Background(), "pre-login-id"); !errors.Is(err, ErrSessionNotFound) {
		t.Error("the pre-login session was not deleted")
	}
	if _, err := store.Get(context.Background(), sess.ID); err != nil {
		t.Errorf("the new session was not saved: %v", err)
	}
}

// TestRotateLogin_OldCSRFTokenRejectedAfter is the issue's second test:
// the CSRF token issued before login is rejected on a request made after.
//
// csrf.Rotate's own validation is stateless HMAC over (cookie value,
// token) — there is no server-side denylist of old pairs, so the old
// cookie presented together with the old token it was issued with still
// validates on its own; that pair is simply never presented again once
// the browser adopts the cookie Rotate just set. The actual attack
// rotation defends against is an attacker who captured the pre-login
// TOKEN (e.g. by reading it out of the login page before authenticating)
// trying to use it once the browser's cookie has moved on: the new cookie
// paired with the stale, pre-login token, which is exactly what this test
// submits.
//
// Negative control: with the call to protector.Rotate removed from
// RotateLogin (keeping only the session id rotation), this test failed —
// via rotatedCSRFCookie's own t.Fatal ("no CSRF cookie was set by
// RotateLogin"), since nothing had rotated the cookie at all, rather than
// via the rejection assertion below. A failure before that assertion is
// still a failure of the property under test: without Rotate, there is no
// new cookie for a stale token to be stale against. Verified by hand,
// restored before committing.
func TestRotateLogin_OldCSRFTokenRejectedAfter(t *testing.T) {
	store := newFakeSessionStore()
	protector := newTestProtector(t)
	oldToken, oldCookie := obtainToken(t, protector)

	rec := httptest.NewRecorder()
	r := csrfRequest(oldCookie)
	if _, err := RotateLogin(r.Context(), rec, r, protector, store,
		"", "alice@example.com", time.Now(), time.Hour, 24*time.Hour); err != nil {
		t.Fatalf("RotateLogin: %v", err)
	}
	newCookie := rotatedCSRFCookie(t, rec)

	// The browser's cookie jar now holds newCookie (Rotate just set it).
	// An attacker who only captured the pre-login token submits it against
	// that new cookie.
	replay := csrfRequest(newCookie)
	replay.Header.Set(csrf.DefaultHeaderName, oldToken)
	replayRec := httptest.NewRecorder()
	reached := false

	protector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})).ServeHTTP(replayRec, replay)

	if reached || replayRec.Code != http.StatusForbidden {
		t.Errorf("a request with the new cookie and the pre-login CSRF token was not rejected (reached handler=%v, status=%d)", reached, replayRec.Code)
	}
}

// rotatedCSRFCookie extracts the CSRF cookie RotateLogin's call to
// protector.Rotate set on rec.
func rotatedCSRFCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrf.DefaultCookieName {
			return c
		}
	}
	t.Fatal("no CSRF cookie was set by RotateLogin")
	return nil
}

// TestRotateLogin_HandlesHeadersAlreadySent is the issue's third test:
// calling Rotate after the response has begun is handled, not ignored.
//
// The request must carry a valid (token, cookie) pair, not just the
// cookie: csrfRequest alone is rejected by protector.Middleware's own
// admission check (missing token header) before the inner handler — the
// code actually under test — ever runs, which would make the assertion
// below pass vacuously regardless of what RotateLogin does.
//
// Negative control, first attempt: using the bare csrfRequest helper (no
// token header), this test passed even with the Rotate call's error
// swallowed inside RotateLogin — not because headers-already-sent was
// handled, but because Middleware's 403 on the missing token meant the
// handler, and the assertion inside it, never ran at all (confirmed via a
// probe: ran=false, rec.Code=403). Recorded for the same reason the wrong
// controls in #16, #18 and #19 were, and fixed by switching to
// validCSRFRequest so the handler is actually reached.
//
// Negative control, second attempt (against the fix): with
// protector.Rotate's error swallowed instead of returned, this test
// failed correctly — the handler ran, RotateLogin returned a nil error,
// and the errors.Is assertion fired. Verified by hand, restored before
// committing.
func TestRotateLogin_HandlesHeadersAlreadySent(t *testing.T) {
	store := newFakeSessionStore()
	protector := newTestProtector(t)
	token, cookie := obtainToken(t, protector)

	rec := httptest.NewRecorder()
	r := validCSRFRequest(token, cookie)
	reached := false

	protector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK) // the response has now begun
		_, err := RotateLogin(r.Context(), w, r, protector, store,
			"", "alice@example.com", time.Now(), time.Hour, 24*time.Hour)
		if !errors.Is(err, csrf.ErrHeadersAlreadySent) {
			t.Errorf("RotateLogin after headers sent = %v, want it to wrap csrf.ErrHeadersAlreadySent", err)
		}
	})).ServeHTTP(rec, r)

	if !reached {
		t.Fatal("protector.Middleware rejected the request before the handler ran — test fixture is broken")
	}
}
