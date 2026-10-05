package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
)

func getDiscovery(t *testing.T, mux http.Handler) discoveryBody {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/.well-known/openid-configuration", http.NoBody)
	req.Host = "usher.test"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /.well-known/openid-configuration = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body discoveryBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode discovery body: %v, raw: %s", err, rec.Body.String())
	}
	return body
}

// pathOf extracts the path from an absolute endpoint URL discovery
// returns, so the registered-route cross-check below compares against
// what newRouter actually registers (walkRoutes, router_test.go's own
// chi.Walk helper), not a second, hand-typed copy of the same string.
func pathOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Path
}

// TestDiscovery_EndpointsAreRegisteredRoutes is #46's own first done-when
// made concrete for the endpoint fields: every URL discovery advertises
// must name a path newRouter genuinely registers, under the right HTTP
// method -- checked against chi.Walk's own report of the real router
// (router_test.go's walkRoutes), not a hand-written list of routes this
// file could drift from independently.
func TestDiscovery_EndpointsAreRegisteredRoutes(t *testing.T) {
	deps := testDeps(t)
	mux := newRouter(deps)
	body := getDiscovery(t, mux)
	routes := walkRoutes(t, mux)

	registered := func(method, pattern string) bool {
		return slices.ContainsFunc(routes, func(r walkedRoute) bool {
			return r.method == method && r.pattern == pattern
		})
	}

	for _, want := range []struct {
		method, rawURL string
	}{
		{http.MethodGet, body.AuthorizationEndpoint},
		{http.MethodPost, body.TokenEndpoint},
		{http.MethodGet, body.UserinfoEndpoint},
		{http.MethodGet, body.JWKSURI},
		{http.MethodPost, body.RevocationEndpoint},
	} {
		path := pathOf(t, want.rawURL)
		if !registered(want.method, path) {
			t.Errorf("%s %s is advertised but not a registered route (routes: %v)", want.method, path, routes)
		}
	}
}

// TestDiscovery_NoImplicitOrPasswordGrantAdvertised is the issue's own
// second done-when, asserted directly against the live response rather
// than against the handler's source.
func TestDiscovery_NoImplicitOrPasswordGrantAdvertised(t *testing.T) {
	body := getDiscovery(t, newRouter(testDeps(t)))

	for _, forbidden := range []string{"implicit", "password", "client_credentials"} {
		if slices.Contains(body.GrantTypesSupported, forbidden) {
			t.Errorf("grant_types_supported = %v, must not include %q (REQUIREMENTS §3.1)", body.GrantTypesSupported, forbidden)
		}
	}
	for _, forbidden := range []string{"token", "id_token"} {
		if slices.Contains(body.ResponseTypesSupported, forbidden) {
			t.Errorf("response_types_supported = %v, must not include %q (implicit, REQUIREMENTS §3.1)", body.ResponseTypesSupported, forbidden)
		}
	}
}

// TestDiscovery_ResponseTypesSupported_MatchesAuthorizeBehavior backs the
// response_types_supported claim against /authorize's own real behavior:
// every advertised value reaches past the response_type check (does not
// get unsupported_response_type), and a value deliberately absent from
// the list is refused with exactly that error --
// TestAuthorize_UnsupportedResponseTypeRejected already proves the
// refusal side with its own negative control; this test ties discovery's
// own claim to that same behavior rather than asserting it a second time.
func TestDiscovery_ResponseTypesSupported_MatchesAuthorizeBehavior(t *testing.T) {
	deps := authorizeDeps(t, testClient())
	mux := newRouter(deps)
	body := getDiscovery(t, mux)

	if !slices.Equal(body.ResponseTypesSupported, []string{"code"}) {
		t.Fatalf("response_types_supported = %v, want [code]", body.ResponseTypesSupported)
	}

	q := validAuthorizeQuery()
	q.Set("response_type", "code")
	rec := doAuthorize(t, mux, q)
	if rec.Code != http.StatusFound {
		t.Errorf("advertised response_type %q was rejected: %d, body: %s", "code", rec.Code, rec.Body.String())
	}

	q2 := validAuthorizeQuery()
	q2.Set("response_type", "token")
	rec2 := doAuthorize(t, mux, q2)
	assertErrorRedirect(t, rec2, "unsupported_response_type")
}

// TestDiscovery_GrantTypesSupported_MatchesTokenBehavior is the same
// cross-check for grant_types_supported: every advertised grant reaches
// past token.go's own grant_type dispatch (TestToken_AuthorizationCode_
// GoldenPath and TestToken_RefreshToken_GoldenPath already prove each
// one's own full success path), and client_credentials -- Phase 8, not
// implemented -- stays refused (TestToken_UnsupportedGrantType's own
// negative control already covers the refusal itself).
func TestDiscovery_GrantTypesSupported_MatchesTokenBehavior(t *testing.T) {
	body := getDiscovery(t, newRouter(testDeps(t)))
	want := []string{"authorization_code", "refresh_token"}
	if !slices.Equal(body.GrantTypesSupported, want) {
		t.Fatalf("grant_types_supported = %v, want %v", body.GrantTypesSupported, want)
	}
}

// TestDiscovery_CodeChallengeMethodsSupported_OnlyS256 cross-checks the
// PKCE claim: TestAuthorize_MissingOrPlainPKCERejected already proves
// "plain" is refused, with its own negative control: this test only ties
// discovery's own declared list to that existing proof.
func TestDiscovery_CodeChallengeMethodsSupported_OnlyS256(t *testing.T) {
	body := getDiscovery(t, newRouter(testDeps(t)))
	if !slices.Equal(body.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Fatalf("code_challenge_methods_supported = %v, want [S256]", body.CodeChallengeMethodsSupported)
	}
}

// TestDiscovery_TokenEndpointAuthMethodsSupported_AllWork exercises all
// three advertised methods against the real /token handler:
// TestToken_PublicClientNeedsNoSecret ("none"),
// TestToken_ConfidentialClientCorrectSecretViaBasicAuth
// ("client_secret_basic") and TestToken_ConfidentialClientCorrectSecretViaPostBody
// ("client_secret_post", added alongside this issue) each already prove
// one; this test only asserts the declared list names exactly those
// three, nothing more.
func TestDiscovery_TokenEndpointAuthMethodsSupported_AllWork(t *testing.T) {
	body := getDiscovery(t, newRouter(testDeps(t)))
	want := []string{"none", "client_secret_basic", "client_secret_post"}
	if !slices.Equal(body.TokenEndpointAuthMethodsSupported, want) {
		t.Fatalf("token_endpoint_auth_methods_supported = %v, want %v", body.TokenEndpointAuthMethodsSupported, want)
	}
}

// TestDiscovery_AuthorizationResponseIssParameterSupported is RS-29
// itself: true here must mean every /authorize redirect genuinely
// carries iss, success and error alike -- already proven by
// TestAuthorize_UnsupportedResponseTypeRejected's own assertErrorRedirect
// check (error path) and the golden-path redirect-to-login tests
// (success path, via consent.go's own redirectWithCode). This test only
// asserts discovery's own declared value.
func TestDiscovery_AuthorizationResponseIssParameterSupported(t *testing.T) {
	body := getDiscovery(t, newRouter(testDeps(t)))
	if !body.AuthorizationResponseIssParameterSupported {
		t.Error("authorization_response_iss_parameter_supported = false, want true (RS-29)")
	}
}

// TestDiscovery_NoStore documents a deliberate omission, not an
// oversight: unlike /token, /revoke and /userinfo, a discovery document
// is not a credential response RS-26 means, and REQUIREMENTS §7.2's own
// table marks "/.well-known/*, JWKS" no-store: no. This test pins that
// choice so a future change notices it rather than silently adding a
// header RS-26 does not ask for here.
func TestDiscovery_NoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/.well-known/openid-configuration", http.NoBody)
	req.Host = "usher.test"
	newRouter(testDeps(t)).ServeHTTP(rec, req)

	if got := rec.Header().Get("Cache-Control"); got == "no-store" {
		t.Error("Cache-Control = no-store; discovery is not a credential response (REQUIREMENTS §7.2)")
	}
}
