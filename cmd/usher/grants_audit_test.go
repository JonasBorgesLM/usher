package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/JonasBorgesLM/usher/internal/audit"
)

// ADR-0023, Decision 2: every action that grants privilege is recorded before
// it takes effect, and denied when the record fails. These tests drive each
// grant through the router twice, once with a recorder that accepts and once
// with one that fails, as a poisoned or full audit log would.

var errAuditDown = errors.New("audit log poisoned")

func recorderOf(t *testing.T, deps routerDeps) *audit.MemoryRecorder {
	t.Helper()
	m, ok := deps.Recorder.(*audit.MemoryRecorder)
	if !ok {
		t.Fatalf("deps.Recorder is %T, want *audit.MemoryRecorder", deps.Recorder)
	}
	return m
}

// grant is one privilege-granting request, set up on fresh deps.
type grant struct {
	name string
	// typ, subject and client are the Record the grant must produce.
	typ             audit.EventType
	subject, client string
	// deps builds the deps the grant's own tests use.
	deps func(t *testing.T) routerDeps
	// run performs the grant on mux and returns the response. fail, if not
	// nil, is set on the recorder just before the grant's own request.
	run func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder
	// granted reports whether the grant took effect: a token in the body, a
	// consent row, a session cookie.
	granted func(t *testing.T, deps routerDeps, rec *httptest.ResponseRecorder) bool
}

func tokenIssued(_ *testing.T, _ routerDeps, rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "access_token")
}

func grants() []grant {
	return []grant{
		{
			name: "authorization_code", typ: audit.EventTokenIssued, subject: testSubject, client: testClientID,
			deps: func(t *testing.T) routerDeps {
				c := testClient()
				c.GrantTypes = []string{"authorization_code"}
				c.Audiences = []string{"https://rs.example"}
				return tokenDeps(t, c)
			},
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})
				recorderOf(t, deps).Fail(fail)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))
				return rec
			},
			granted: tokenIssued,
		},
		{
			name: "refresh_token", typ: audit.EventTokenIssued, subject: testSubject, client: testClientID,
			deps: func(t *testing.T) routerDeps {
				c := testClient()
				c.GrantTypes = []string{"authorization_code", "refresh_token"}
				c.Audiences = []string{"https://rs.example"}
				return tokenDeps(t, c)
			},
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				// The code exchange that yields the refresh token is recorded
				// too; the failure applies to the refresh only.
				seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))
				issued := decodeTokenSuccess(t, rec)
				if issued.RefreshToken == "" {
					t.Fatal("the code exchange issued no refresh token")
				}
				recorderOf(t, deps).Fail(fail)
				form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "client_id": {testClientID}}
				rec = httptest.NewRecorder()
				mux.ServeHTTP(rec, postToken(form, "", ""))
				return rec
			},
			granted: tokenIssued,
		},
		{
			name: "client_credentials", typ: audit.EventTokenIssued, subject: "", client: testClientID,
			deps: func(t *testing.T) routerDeps { return tokenDeps(t, clientCredentialsTestClient("cc-secret")) },
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				recorderOf(t, deps).Fail(fail)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, postToken(clientCredentialsForm("read"), testClientID, "cc-secret"))
				return rec
			},
			granted: tokenIssued,
		},
		{
			name: "consent", typ: audit.EventConsentGranted, subject: testSubject, client: testClientID,
			deps: func(t *testing.T) routerDeps { return consentDeps(t, consentTestClient()) },
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				c := seedChallenge(t, deps, "challenge-1", testClientID, []string{"openid", "profile"})
				token, cookie, _ := getConsent(t, mux, c.ID)
				recorderOf(t, deps).Fail(fail)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, postConsent(token, cookie, c.ID, "allow"))
				return rec
			},
			granted: func(t *testing.T, deps routerDeps, rec *httptest.ResponseRecorder) bool {
				_, ok, err := deps.Consents.Granted(context.Background(), testSubject, testClientID)
				if err != nil {
					t.Fatal(err)
				}
				return ok || rec.Code == http.StatusFound
			},
		},
		{
			name: "login", typ: audit.EventLoginAttempt, subject: "user-1", client: "",
			deps: func(t *testing.T) routerDeps { return testDeps(t) },
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				c := seedPendingChallenge(t, deps, "challenge-1", testClientID, "", nil)
				token, cookie, _ := getLogin(t, mux)
				recorderOf(t, deps).Fail(fail)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, postLoginWithChallenge(token, cookie, c.ID, testIdentifier, testPassword))
				return rec
			},
			granted: func(_ *testing.T, _ routerDeps, rec *httptest.ResponseRecorder) bool {
				return sessionCookieFrom(rec) != nil || rec.Code == http.StatusSeeOther
			},
		},
	}
}

// Each grant, with a recorder that accepts, takes effect and leaves exactly
// one record of its kind, for the right person and client, with an ID.
func TestGrants_AreRecorded(t *testing.T) {
	for _, g := range grants() {
		t.Run(g.name, func(t *testing.T) {
			deps := g.deps(t)
			mux := newRouter(deps)
			rec := g.run(t, deps, mux, nil)
			if !g.granted(t, deps, rec) {
				t.Fatalf("the grant did not take effect: %d %s", rec.Code, rec.Body.String())
			}
			records := recorderOf(t, deps).Records()
			last := records[len(records)-1]
			if last.Type != g.typ || last.Outcome != audit.OutcomeSuccess || last.Subject != g.subject || last.ClientID != g.client || last.ID == "" {
				t.Fatalf("record = %+v, want %s for subject %q, client %q, with an ID", last, g.typ, g.subject, g.client)
			}
		})
	}
}

// Each grant, with a recorder that fails, is denied: no token, no consent
// row, no session; and nothing of it was recorded.
//
// Seen failing, case by case, with each Record call's error ignored.
func TestGrants_FailClosedWhenTheRecordFails(t *testing.T) {
	ran := 0
	for _, g := range grants() {
		t.Run(g.name, func(t *testing.T) {
			deps := g.deps(t)
			m := recorderOf(t, deps)
			mux := newRouter(deps)
			rec := g.run(t, deps, mux, errAuditDown)
			if g.granted(t, deps, rec) {
				t.Fatalf("the grant took effect with the audit log down: %d %s", rec.Code, rec.Body.String())
			}
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rec.Code)
			}
			for _, r := range m.Records() {
				if r.Type == g.typ && g.name != "refresh_token" {
					t.Fatalf("a %s record was kept with the log down: %+v", g.typ, r)
				}
			}
			ran++
		})
	}
	if ran != 5 {
		t.Fatalf("ran %d grants, want 5", ran)
	}
}

// A router without a Recorder would grant nothing, so newRouter refuses to
// build one: a wiring mistake surfaces at startup, not as a replica that
// denies every login.
//
// Seen failing with the nil check removed: newRouter built the router.
func TestNewRouter_RequiresARecorder(t *testing.T) {
	deps := testDeps(t)
	deps.Recorder = nil
	defer func() {
		if recover() == nil {
			t.Fatal("newRouter built a router with no Recorder")
		}
	}()
	newRouter(deps)
}
