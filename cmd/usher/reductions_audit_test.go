package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/internal/session"
)

// ADR-0023, Decision 2: an action that reduces privilege executes whatever
// its record does, and so does an informational event. Each is driven
// through the router with a recorder that accepts, and with one that is
// down, as a poisoned log is.

// errLogDown is what a poisoned tally log returns: Reductions gives up on it
// at once, so these tests start no background retry.
var errLogDown = fmt.Errorf("%w: poisoned", audit.ErrRecorderDown)

type reduction struct {
	name            string
	typ             audit.EventType
	outcome         audit.Outcome
	subject, client string
	deps            func(t *testing.T) routerDeps
	// run performs the action; fail, if not nil, is set on the recorder
	// just before the action's own request.
	run func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder
	// executed reports whether the action took effect.
	executed func(t *testing.T, deps routerDeps, rec *httptest.ResponseRecorder) bool
}

func familyRevoked(t *testing.T, deps routerDeps) bool {
	t.Helper()
	fam, _, err := deps.Families.Lookup(context.Background(), sha256.Sum256([]byte(testRefreshToken)))
	if err != nil {
		t.Fatal(err)
	}
	return fam.RevokedAt != nil
}

func reductions() []reduction {
	return []reduction{
		{
			name: "revoke a refresh token", typ: audit.EventRevocation, outcome: audit.OutcomeSuccess,
			subject: testSubject, client: testClientID,
			deps: func(t *testing.T) routerDeps {
				deps, _ := revokeDeps(t, revokeTestClient("s3cr3t"))
				deps.Families.(*fakeFamilyStore).seedFamily(oauth.Family{ClientID: testClientID, Subject: testSubject}, testRefreshToken)
				return deps
			},
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				recorderOf(t, deps).Fail(fail)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, postRevoke(url.Values{"token": {testRefreshToken}}, testClientID, "s3cr3t"))
				return rec
			},
			executed: func(t *testing.T, deps routerDeps, rec *httptest.ResponseRecorder) bool {
				return rec.Code == http.StatusOK && familyRevoked(t, deps)
			},
		},
		{
			name: "refresh token reuse", typ: audit.EventRefreshReuse, outcome: audit.OutcomeFailure,
			subject: testSubject, client: testClientID,
			deps: func(t *testing.T) routerDeps {
				deps := tokenDeps(t, testClient())
				deps.Families.(*fakeFamilyStore).seedFamily(oauth.Family{ClientID: testClientID, Subject: testSubject,
					Scope: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour)}, testRefreshToken)
				return deps
			},
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				// The first exchange is a grant, recorded and allowed; the
				// failure applies to the replay.
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, postRefreshToken(validRefreshTokenForm(), "", ""))
				if rec.Code != http.StatusOK {
					t.Fatalf("first exchange = %d %s", rec.Code, rec.Body.String())
				}
				recorderOf(t, deps).Fail(fail)
				rec = httptest.NewRecorder()
				mux.ServeHTTP(rec, postRefreshToken(validRefreshTokenForm(), "", ""))
				return rec
			},
			executed: func(t *testing.T, deps routerDeps, rec *httptest.ResponseRecorder) bool {
				return rec.Code == http.StatusBadRequest && familyRevoked(t, deps)
			},
		},
		{
			name: "logout", typ: audit.EventLogout, outcome: audit.OutcomeSuccess, subject: testIdentifier,
			deps: func(t *testing.T) routerDeps { return testDeps(t) },
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				seedSession(t, deps, "raw-session-1", testIdentifier, deps.Now())
				token, csrfCookie, _ := getLogout(t, mux)
				recorderOf(t, deps).Fail(fail)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, postLogout(token, csrfCookie, sessionCookie("raw-session-1")))
				return rec
			},
			executed: func(t *testing.T, deps routerDeps, rec *httptest.ResponseRecorder) bool {
				_, err := deps.Sessions.Get(context.Background(), "raw-session-1")
				return rec.Code == http.StatusOK && errors.Is(err, session.ErrSessionNotFound)
			},
		},
		{
			name: "failed login, existing user", typ: audit.EventLoginAttempt, outcome: audit.OutcomeFailure, subject: "user-1",
			deps: func(t *testing.T) routerDeps { return testDeps(t) },
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				return postFailedLogin(t, deps, mux, fail, testIdentifier)
			},
			executed: loginRefused,
		},
		{
			// The typed identifier is in no record: an attacker can type
			// any number of them.
			name: "failed login, unknown identifier", typ: audit.EventLoginAttempt, outcome: audit.OutcomeFailure, subject: "",
			deps: func(t *testing.T) routerDeps { return testDeps(t) },
			run: func(t *testing.T, deps routerDeps, mux *chi.Mux, fail error) *httptest.ResponseRecorder {
				return postFailedLogin(t, deps, mux, fail, "nobody@example.com")
			},
			executed: loginRefused,
		},
	}
}

func postFailedLogin(t *testing.T, deps routerDeps, mux *chi.Mux, fail error, identifier string) *httptest.ResponseRecorder {
	t.Helper()
	token, cookie, _ := getLogin(t, mux)
	recorderOf(t, deps).Fail(fail)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postLoginWithChallenge(token, cookie, "", identifier, "wrong password"))
	return rec
}

// loginRefused: the failed login got its ordinary answer, the form again
// with no session.
func loginRefused(_ *testing.T, _ routerDeps, rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusOK && sessionCookieFrom(rec) == nil
}

// Each reduction, and each failed login, is recorded with the right type,
// outcome, person and client.
func TestReductions_AreRecorded(t *testing.T) {
	for _, c := range reductions() {
		t.Run(c.name, func(t *testing.T) {
			deps := c.deps(t)
			rec := c.run(t, deps, newRouter(deps), nil)
			if !c.executed(t, deps, rec) {
				t.Fatalf("the action did not execute: %d %s", rec.Code, rec.Body.String())
			}
			records := recorderOf(t, deps).Records()
			last := records[len(records)-1]
			if last.Type != c.typ || last.Outcome != c.outcome || last.Subject != c.subject || last.ClientID != c.client || last.ID == "" {
				t.Fatalf("record = %+v, want %s/%s for subject %q, client %q", last, c.typ, c.outcome, c.subject, c.client)
			}
		})
	}
}

// With the log down, each still executes and answers as it always does.
//
// Seen failing, each case run on its own, with Reductions.Record made to
// panic on a failed record, as a handler that refused on its record would.
func TestReductions_ExecuteWhenTheRecordFails(t *testing.T) {
	ran := 0
	for _, c := range reductions() {
		t.Run(c.name, func(t *testing.T) {
			deps := c.deps(t)
			rec := c.run(t, deps, newRouter(deps), errLogDown)
			if !c.executed(t, deps, rec) {
				t.Fatalf("the action did not execute with the log down: %d %s", rec.Code, rec.Body.String())
			}
			ran++
		})
	}
	if ran != 5 {
		t.Fatalf("ran %d cases, want 5", ran)
	}
}
