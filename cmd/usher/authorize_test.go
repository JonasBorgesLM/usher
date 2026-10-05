package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JonasBorgesLM/usher/internal/identity"
)

const testClientID = "test-client"
const testRedirectURI = "https://client.example/callback"

func testClient() identity.Client {
	return identity.Client{
		ID:           testClientID,
		Confidential: false,
		RedirectURIs: []string{testRedirectURI},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
	}
}

// validAuthorizeQuery returns a complete, valid /authorize query -- every
// test below is this with exactly one value mutated, the same "single
// mutation from a known-good baseline" shape router_test.go's own tests
// already use.
func validAuthorizeQuery() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"state":                 {"xyz123"},
		"scope":                 {"openid"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
}

func doAuthorize(t *testing.T, mux http.Handler, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/authorize?"+q.Encode(), http.NoBody)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func authorizeDeps(t *testing.T, clients ...identity.Client) routerDeps {
	t.Helper()
	deps := testDeps(t)
	deps.Clients = clients
	return deps
}

// TestAuthorize_ValidRequestRedirectsToLogin is the control case every
// other test below mutates exactly one value away from.
func TestAuthorize_ValidRequestRedirectsToLogin(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	rec := doAuthorize(t, mux, validAuthorizeQuery())

	if rec.Code != http.StatusFound {
		t.Fatalf("GET /authorize with a valid request = %d, want %d, body: %s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Path != "/login" {
		t.Errorf("Location path = %q, want /login", loc.Path)
	}
	if loc.Query().Get("login_challenge") == "" {
		t.Error("Location has no login_challenge")
	}
}

// TestAuthorize_LoginURLCarriesOnlyChallengeID is #27's own done-when
// (RS-05: no request parameter in the query string): the redirect to
// /login carries exactly one query parameter, login_challenge, never the
// original client_id, redirect_uri, scope, state or code_challenge.
//
// Negative control: with the redirect target in ServeHTTP changed to
// "/login?"+q.Encode()+"&login_challenge="+id (forwarding the original
// query alongside the challenge id), this test failed -- the Location
// carried 8 parameters instead of 1, including client_id and
// code_challenge in the clear. Verified by hand, restored before
// committing.
func TestAuthorize_LoginURLCarriesOnlyChallengeID(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	rec := doAuthorize(t, mux, validAuthorizeQuery())

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	q := loc.Query()
	if len(q) != 1 {
		t.Fatalf("Location query has %d parameters, want exactly 1 (login_challenge): %s", len(q), loc)
	}
	if _, ok := q["login_challenge"]; !ok {
		t.Errorf("Location's one parameter is not login_challenge: %s", loc)
	}
}

// TestAuthorize_UnknownClientRendersLocally is RS-28 step 1: no redirect
// target exists yet, so none is used.
//
// Negative control: an unknown client_id changed to redirect the error
// (using the request's own, never-verified redirect_uri) instead of
// rendering locally. This test failed -- the request redirected straight
// to the attacker-suppliable redirect_uri with an error attached, exactly
// the failure mode the issue itself names. Disabling `lookupClient`'s own
// check first, as a simpler mutation, was tried and did not produce a
// distinguishable failure: the zero-value Client it falls through to has
// no RedirectURIs, so step 2 also renders locally -- a coincidence of
// this code's structure, not evidence the check is unnecessary. Verified
// by hand, restored before committing.
func TestAuthorize_UnknownClientRendersLocally(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	q := validAuthorizeQuery()
	q.Set("client_id", "never-registered")
	rec := doAuthorize(t, mux, q)

	if rec.Code == http.StatusFound {
		t.Fatalf("GET /authorize with an unknown client_id redirected (Location: %s), want a local error page", rec.Header().Get("Location"))
	}
	if rec.Header().Get("Location") != "" {
		t.Errorf("a local error response carries a Location header: %s", rec.Header().Get("Location"))
	}
}

// TestAuthorize_UnmatchedRedirectURIRendersLocally is RS-28 step 2: a
// known client, but a redirect_uri it never registered. Still no
// redirect -- RS-28's whole point is that this exact shape, one step
// later, is the open-redirect mistake.
func TestAuthorize_UnmatchedRedirectURIRendersLocally(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	q := validAuthorizeQuery()
	q.Set("redirect_uri", "https://attacker.example/callback")
	rec := doAuthorize(t, mux, q)

	if rec.Code == http.StatusFound {
		t.Fatalf("GET /authorize with an unregistered redirect_uri redirected (Location: %s), want a local error page", rec.Header().Get("Location"))
	}
}

// TestAuthorize_BothRedirectURIAndPKCEFailGetsNonRedirectingResponse is
// the issue's own first done-when item, and RS-28's central claim: a
// request that fails BOTH the redirect_uri check and (hypothetically)
// PKCE must get the non-redirecting response. Checking PKCE first "because
// it's cheap" would redirect an error to an unverified target.
//
// Negative control: with RS-28's step order reversed in ServeHTTP (PKCE
// checked before redirect_uri), this test failed -- the response was a
// redirect to the attacker-supplied, unregistered redirect_uri, carrying
// an invalid_request error. Verified by hand (reverted immediately,
// recorded rather than left in place even temporarily longer than the
// check took), restored before committing.
func TestAuthorize_BothRedirectURIAndPKCEFailGetsNonRedirectingResponse(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	q := validAuthorizeQuery()
	q.Set("redirect_uri", "https://attacker.example/callback") // fails step 2
	q.Del("code_challenge")                                    // would also fail step 3's PKCE check
	rec := doAuthorize(t, mux, q)

	if rec.Code == http.StatusFound {
		t.Fatalf("a request failing both redirect_uri and PKCE redirected (Location: %s), want the non-redirecting response", rec.Header().Get("Location"))
	}
}

// TestAuthorize_RedirectURIVariantsRejected is the issue's second
// done-when: prefix, trailing-slash, case and encoded variants of a
// registered URI are all rejected (RS-02 -- exact string match, no
// normalization).
//
// Negative control: with exactRedirectURIMatch widened to
// strings.EqualFold(candidate, r) || strings.HasPrefix(candidate, r), the
// prefix, trailing-slash and case sub-tests all failed -- each was
// accepted when it should have been rejected. The percent-encoded
// sub-test still passed even under that weakened check, which is
// expected: neither case-folding nor a prefix check happens to cover that
// variant either, so it is not this particular mutation's job to catch
// it -- the other three failing is what confirms the match really was
// exact before. Verified by hand, restored before committing.
func TestAuthorize_RedirectURIVariantsRejected(t *testing.T) {
	variants := map[string]string{
		"prefix (registered URI plus extra path)": testRedirectURI + "/extra",
		"trailing slash":         testRedirectURI + "/",
		"case (host uppercased)": "https://CLIENT.example/callback",
		"percent-encoded path":   "https://client.example/%63allback",
	}
	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			mux := newRouter(authorizeDeps(t, testClient()))
			q := validAuthorizeQuery()
			q.Set("redirect_uri", variant)
			rec := doAuthorize(t, mux, q)

			if rec.Code == http.StatusFound {
				t.Errorf("redirect_uri variant %q (%s) was accepted, want rejection", variant, name)
			}
		})
	}
}

// TestAuthorize_MissingOrPlainPKCERejected is the issue's third done-when,
// the PKCE half: both a missing code_challenge and code_challenge_method=
// plain are rejected (RS-01).
//
// Negative control: with the `code_challenge_method != "S256"` half of the
// check removed, the "plain" sub-test failed -- the request was accepted
// and redirected all the way to /login instead of back to the client with
// invalid_request, exactly the PKCE-downgrade RS-01 exists to block.
// Verified by hand, restored before committing.
func TestAuthorize_MissingOrPlainPKCERejected(t *testing.T) {
	t.Run("missing code_challenge", func(t *testing.T) {
		mux := newRouter(authorizeDeps(t, testClient()))
		q := validAuthorizeQuery()
		q.Del("code_challenge")
		rec := doAuthorize(t, mux, q)
		assertErrorRedirect(t, rec, "invalid_request")
	})

	t.Run("code_challenge_method=plain", func(t *testing.T) {
		mux := newRouter(authorizeDeps(t, testClient()))
		q := validAuthorizeQuery()
		q.Set("code_challenge_method", "plain")
		rec := doAuthorize(t, mux, q)
		assertErrorRedirect(t, rec, "invalid_request")
	})
}

// TestAuthorize_UnsupportedResponseTypeRejected backs discovery.go's own
// response_types_supported: ["code"] claim (#46) -- a value other than
// "code" ("token", implicit's own response_type) must be rejected, the
// same error-redirect shape every other RF-02 Flow 1 step 1 rejection
// uses.
//
// Negative control: with the `q.Get("response_type") != "code"` check
// removed from authorize.go, this test failed -- the request proceeded
// all the way to the redirect-to-/login response discovery's own claim
// says is impossible for anything but "code". Verified by hand, restored
// before committing.
func TestAuthorize_UnsupportedResponseTypeRejected(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	q := validAuthorizeQuery()
	q.Set("response_type", "token")
	rec := doAuthorize(t, mux, q)
	assertErrorRedirect(t, rec, "unsupported_response_type")
}

// assertErrorRedirect confirms rec is a redirect to testRedirectURI
// carrying the given RFC 6749 error code, the original state, and iss.
func assertErrorRedirect(t *testing.T, rec *httptest.ResponseRecorder, wantError string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("response = %d, want %d (redirect), body: %s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Query().Get("error"); got != wantError {
		t.Errorf("error = %q, want %q (Location: %s)", got, wantError, loc)
	}
	if got := loc.Query().Get("state"); got != "xyz123" {
		t.Errorf("state = %q, want the original %q echoed back (Location: %s)", got, "xyz123", loc)
	}
	if got := loc.Query().Get("iss"); got == "" {
		t.Errorf("error redirect carries no iss (Location: %s)", loc)
	}
}

// TestAuthorize_MissingStateRejected is the issue's third done-when, the
// state half: state is required.
//
// Negative control: with the `state == ""` check removed, this test
// failed -- a request with no state redirected straight past it to the
// PKCE check (which happened to also pass), landing on /login instead of
// an invalid_request error. Verified by hand, restored before committing.
func TestAuthorize_MissingStateRejected(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	q := validAuthorizeQuery()
	q.Del("state")
	rec := doAuthorize(t, mux, q)

	if rec.Code != http.StatusFound {
		t.Fatalf("GET /authorize with no state = %d, want %d (redirect with an error)", rec.Code, http.StatusFound)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if got := loc.Query().Get("error"); got != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", got)
	}
}

// TestAuthorize_StateEchoedOnError is the other half of "state required
// and echoed": the redirect carries the exact state value, unchanged. #26
// has no success-to-client redirect yet (that is #29/#30, once a code
// exists) -- the state this test can observe now is the one echoed back
// on an error, since that is the only redirect-to-client path #26 builds.
func TestAuthorize_StateEchoedOnError(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	q := validAuthorizeQuery()
	q.Set("state", `state-with-"quotes"-and-spaces here`)
	q.Del("code_challenge") // force an error redirect to inspect
	rec := doAuthorize(t, mux, q)

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Query().Get("state"); got != `state-with-"quotes"-and-spaces here` {
		t.Errorf("state = %q, want it echoed unchanged", got)
	}
}

// TestAuthorize_InvalidScopeRejected confirms scope ⊆ client.Scopes is
// enforced (RS-28 step 3's "everything else").
func TestAuthorize_InvalidScopeRejected(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	q := validAuthorizeQuery()
	q.Set("scope", "openid admin")
	rec := doAuthorize(t, mux, q)
	assertErrorRedirect(t, rec, "invalid_scope")
}

// TestAuthorize_IssPresentOnErrorRedirect is the issue's fourth done-when:
// iss present on error redirects (RS-29/RFC 9207). The success half is
// exercised by TestAuthorize_StateEchoedOnError's sibling assertions and
// by assertErrorRedirect's own check, shared across every error-redirect
// test above; this test isolates iss specifically against a negative
// control.
//
// Negative control: with `q.Set("iss", h.issuer)` removed from
// redirectError, this test failed -- the redirect carried no iss
// parameter at all. Verified by hand, restored before committing.
func TestAuthorize_IssPresentOnErrorRedirect(t *testing.T) {
	mux := newRouter(authorizeDeps(t, testClient()))
	q := validAuthorizeQuery()
	q.Del("code_challenge")
	rec := doAuthorize(t, mux, q)

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Query().Get("iss"); got != "https://usher.test" {
		t.Errorf("iss = %q, want %q", got, "https://usher.test")
	}
}
