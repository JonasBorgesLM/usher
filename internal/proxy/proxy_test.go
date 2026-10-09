package proxy

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/JonasBorgesLM/bastion"
	"github.com/JonasBorgesLM/usher/internal/rbac"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

const (
	testKID       = "test-key"
	testIssuer    = "https://usher.test"
	testAudience  = "https://rs.example"
	testAudienceB = "https://rs-b.example"
	testClientID  = "client-1"
	testSubject   = "alice"
)

// fakeKeySource is a minimal tokenvalidator.KeySource: this package's own
// tests are about NewHandler's orchestration, not about JWKS resolution,
// which pkg/tokenvalidator's own tests already cover.
type fakeKeySource struct{ pub crypto.PublicKey }

func (f fakeKeySource) Key(context.Context, string) (crypto.PublicKey, tokenvalidator.Algorithm, error) {
	return f.pub, tokenvalidator.RS256, nil
}

func testRSAKeyPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return priv
}

func testValidator(t *testing.T, priv *rsa.PrivateKey) *tokenvalidator.Validator {
	t.Helper()
	v, err := tokenvalidator.New(fakeKeySource{pub: priv.Public()}, []tokenvalidator.Algorithm{tokenvalidator.RS256}, tokenvalidator.WithIssuer(testIssuer))
	if err != nil {
		t.Fatalf("tokenvalidator.New: %v", err)
	}
	return v
}

// accessClaims mirrors cmd/usher/token.go's own accessTokenClaims shape,
// duplicated rather than imported -- internal/proxy must never import
// internal/oauth or cmd/usher (ADR-0001), and pkg/tokenvalidator's own
// tests already duplicate this same shape for the same reason.
type accessClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope,omitempty"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JTI       string   `json:"jti"`
}

func testAccessToken(t *testing.T, priv *rsa.PrivateKey, jti string, scope []string) string {
	t.Helper()
	return testAccessTokenForAudience(t, priv, jti, scope, testAudience)
}

func testAccessTokenForAudience(t *testing.T, priv *rsa.PrivateKey, jti string, scope []string, audience string) string {
	t.Helper()
	now := time.Now()
	claims := accessClaims{
		Issuer: testIssuer, Subject: testSubject, Audience: []string{audience},
		ClientID: testClientID, Scope: strings.Join(scope, " "),
		ExpiresAt: now.Add(5 * time.Minute).Unix(), NotBefore: now.Unix(), IssuedAt: now.Unix(),
		JTI: jti,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	hdrs := jws.NewHeaders()
	if setErr := hdrs.Set(jws.KeyIDKey, testKID); setErr != nil {
		t.Fatalf("set kid: %v", setErr)
	}
	if setErr := hdrs.Set(jws.TypeKey, "at+jwt"); setErr != nil {
		t.Fatalf("set typ: %v", setErr)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return string(signed)
}

// idClaims mirrors cmd/usher/token.go's own idTokenClaims shape (RF-03,
// RF-11), duplicated rather than imported for the same ADR-0001 reason
// accessClaims above is: no client_id, no scope, no jti -- an id_token
// genuinely carries none of those.
type idClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
}

// testIDToken signs a token shaped exactly like cmd/usher/token.go's
// issueIDToken output: typ: id_token in the JWS header (never at+jwt),
// and none of accessClaims' extra fields.
func testIDToken(t *testing.T, priv *rsa.PrivateKey, audience string) string {
	t.Helper()
	now := time.Now()
	claims := idClaims{
		Issuer: testIssuer, Subject: testSubject, Audience: []string{audience},
		ExpiresAt: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	hdrs := jws.NewHeaders()
	if setErr := hdrs.Set(jws.KeyIDKey, testKID); setErr != nil {
		t.Fatalf("set kid: %v", setErr)
	}
	if setErr := hdrs.Set(jws.TypeKey, "id_token"); setErr != nil {
		t.Fatalf("set typ: %v", setErr)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return string(signed)
}

// fakeDenylist is a small, controllable stand-in for Denylist -- the real
// one (internal/store/redis) is proven against real Redis in its own
// integration tests (#38); this file tests NewHandler's own orchestration
// over the interface.
type fakeDenylist struct {
	mu          sync.Mutex
	revoked     map[string]bool
	containsErr error
}

func newFakeDenylist() *fakeDenylist { return &fakeDenylist{revoked: map[string]bool{}} }

func (d *fakeDenylist) Contains(_ context.Context, jti string) (bool, error) {
	if d.containsErr != nil {
		return false, d.containsErr
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.revoked[jti], nil
}

func (d *fakeDenylist) Add(_ context.Context, jti string, _ time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.revoked[jti] = true
	return nil
}

// capturingUpstream is a real network listener (httputil.ReverseProxy
// performs an actual HTTP round trip, loopback or not) that records the
// one request it received, for assertions on exactly what crossed the
// wire.
func capturingUpstream(t *testing.T, status int) (srv *httptest.Server, received func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	var captured http.Header
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		captured = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	received = func() http.Header {
		mu.Lock()
		defer mu.Unlock()
		return captured
	}
	return srv, received
}

func testRoute(t *testing.T, upstream *httptest.Server) Route {
	t.Helper()
	return testRouteWithAudience(t, upstream, testAudience)
}

func testRouteWithAudience(t *testing.T, upstream *httptest.Server, audience string) Route {
	t.Helper()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	return Route{PathPrefix: "/api", Upstream: u, Audience: audience}
}

func proxyRequest(authHeader string, extraHeaders map[string]string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/widgets", http.NoBody)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return req
}

// TestNewHandler_StripsSpoofedSubjectHeader is RS-17's first done-when: a
// client-sent X-Auth-Subject never reaches the upstream.
//
// Negative control: with stripIdentityHeaders's call removed from
// NewHandler's returned handler, this test failed -- the spoofed value
// still reached the upstream before being overwritten was not actually
// what happened; see TestNewHandler_StripsUnknownIdentityNamespaceHeader
// for the mutation that actually distinguishes strip-then-set from
// set-only. Both are kept, run by hand, and restored before committing.
func TestNewHandler_StripsSpoofedSubjectHeader(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	denylist := newFakeDenylist()
	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), denylist, nil, nil, nil)

	token := testAccessToken(t, priv, "jti-1", []string{"openid"})
	req := proxyRequest("Bearer "+token, map[string]string{"X-Auth-Subject": "attacker-controlled"})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := received().Get("X-Auth-Subject"); got != testSubject {
		t.Errorf("upstream saw X-Auth-Subject = %q, want %q (the validated claim, not the client's)", got, testSubject)
	}
}

// TestNewHandler_StripsUnknownIdentityNamespaceHeader is RS-17's own
// "allow-list, not block-list" distinction: a header under the identity
// namespace that NewHandler never explicitly sets (so a block-list
// naming only the three it injects would miss it) still never reaches
// the upstream.
//
// Negative control: with the `stripIdentityHeaders(r)` call removed from
// NewHandler's handler (leaving only the three explicit r.Header.Set
// calls later), this test failed -- X-Auth-Impersonate reached the
// upstream verbatim, proving set-only (a block-list of what this
// package happens to inject) is not equivalent to strip-then-set (an
// allow-list of what survives). Verified by hand, restored before
// committing.
func TestNewHandler_StripsUnknownIdentityNamespaceHeader(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	denylist := newFakeDenylist()
	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), denylist, nil, nil, nil)

	token := testAccessToken(t, priv, "jti-2", []string{"openid"})
	req := proxyRequest("Bearer "+token, map[string]string{"X-Auth-Impersonate": "true"})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := received().Get("X-Auth-Impersonate"); got != "" {
		t.Errorf("upstream saw X-Auth-Impersonate = %q, want empty -- an unrecognized identity-namespace header must still be stripped", got)
	}
}

// TestNewHandler_ConnectionHeaderCannotStripInjectedIdentity is #137 (RS-17,
// RI-04): a client naming the identity headers in Connection must not get
// them removed from the outbound request. Not injection — the client's own
// X-Auth-* are stripped first — but removal broke RI-04's contract that the
// gateway always injects all three.
//
// Negative control: with NewHandler back on Director (headers set on the
// inbound request before ReverseProxy's hop-by-hop removal), this test
// failed — the upstream saw X-Auth-Subject, X-Auth-Client and X-Auth-Scope
// all empty. Verified by hand, restored before committing.
func TestNewHandler_ConnectionHeaderCannotStripInjectedIdentity(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), newFakeDenylist(), nil, nil, nil)
	token := testAccessToken(t, priv, "jti-connection", []string{"openid", "widgets:read"})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, map[string]string{
		"Connection": "X-Auth-Subject, X-Auth-Client, X-Auth-Scope",
	}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	h := received()
	if h == nil {
		t.Fatal("the upstream was never called")
	}
	for _, name := range []string{"X-Auth-Subject", "X-Auth-Client", "X-Auth-Scope"} {
		if h.Get(name) == "" {
			t.Errorf("upstream saw no %s: a client's Connection header removed the gateway's own value", name)
		}
	}
	if got := h.Get("X-Auth-Scope"); got != "openid widgets:read" {
		t.Errorf("X-Auth-Scope = %q, want the token's own scope", got)
	}
}

// TestNewHandler_XForwardedForKeepsDirectorShape pins the X-Forwarded-For
// the upstream sees across the Director -> Rewrite move (#137): the client's
// address appended to whatever chain arrived, exactly as Director mode did.
// The resource server's realip (ADR-0010) reads this header.
func TestNewHandler_XForwardedForKeepsDirectorShape(t *testing.T) {
	cases := []struct {
		name, inbound, want string
	}{
		{"no prior chain", "", "192.0.2.1"},
		{"prior chain", "203.0.113.7", "203.0.113.7, 192.0.2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv := testRSAKeyPair(t)
			upstream, received := capturingUpstream(t, http.StatusOK)
			handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), newFakeDenylist(), nil, nil, nil)
			token := testAccessToken(t, priv, "jti-xff", []string{"openid"})
			extra := map[string]string{}
			if tc.inbound != "" {
				extra["X-Forwarded-For"] = tc.inbound
			}
			req := proxyRequest("Bearer "+token, extra)
			req.RemoteAddr = "192.0.2.1:1234"

			handler.ServeHTTP(httptest.NewRecorder(), req)

			if got := received().Get("X-Forwarded-For"); got != tc.want {
				t.Errorf("upstream X-Forwarded-For = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNewHandler_InjectsValidatedClaims is RF-08/RI-04's own golden path:
// a correctly authenticated request reaches the upstream carrying the
// gateway's own identity headers, derived from the validated token, not
// from anything the client sent.
func TestNewHandler_InjectsValidatedClaims(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	denylist := newFakeDenylist()
	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), denylist, nil, nil, nil)

	token := testAccessToken(t, priv, "jti-3", []string{"openid", "profile"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	h := received()
	if got := h.Get("X-Auth-Subject"); got != testSubject {
		t.Errorf("X-Auth-Subject = %q, want %q", got, testSubject)
	}
	if got := h.Get("X-Auth-Client"); got != testClientID {
		t.Errorf("X-Auth-Client = %q, want %q", got, testClientID)
	}
	if got := h.Get("X-Auth-Scope"); got != "openid profile" {
		t.Errorf("X-Auth-Scope = %q, want %q", got, "openid profile")
	}
}

// TestNewHandler_MissingBearerToken_Unauthorized and the two tests after
// it are RF-08's own "after validating the token" -- there is no
// forwarding at all without one.
func TestNewHandler_MissingBearerToken_Unauthorized(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), newFakeDenylist(), nil, nil, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if received() != nil {
		t.Error("the upstream was called despite no bearer token at all")
	}
}

func TestNewHandler_InvalidToken_Unauthorized(t *testing.T) {
	priv := testRSAKeyPair(t)
	other := testRSAKeyPair(t) // token signed by a key this validator never trusts
	upstream, received := capturingUpstream(t, http.StatusOK)
	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), newFakeDenylist(), nil, nil, nil)

	token := testAccessToken(t, other, "jti-4", []string{"openid"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if received() != nil {
		t.Error("the upstream was called despite a signature that does not verify")
	}
}

// TestNewHandler_RevokedToken_Unauthorized is RF-06/ADR-0014's own
// gateway-local check: a token on the denylist is refused even though
// its own signature and claims are otherwise perfectly valid.
func TestNewHandler_RevokedToken_Unauthorized(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	denylist := newFakeDenylist()
	if err := denylist.Add(context.Background(), "jti-revoked", time.Minute); err != nil {
		t.Fatalf("seed denylist: %v", err)
	}
	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), denylist, nil, nil, nil)

	token := testAccessToken(t, priv, "jti-revoked", []string{"openid"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if received() != nil {
		t.Error("the upstream was called despite a revoked token")
	}
}

// TestNewHandler_DenylistErrorFailsClosed is RNF-04 applied to the
// gateway's own revocation check: an infrastructure failure reading the
// denylist must deny, never silently fall back to "not revoked."
//
// Negative control: with the `err != nil ||` half of the denylist check
// removed from NewHandler (leaving only `revoked`), this test failed --
// a denylist read error let an otherwise-valid token through to the
// upstream. Verified by hand, restored before committing.
func TestNewHandler_DenylistErrorFailsClosed(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	denylist := newFakeDenylist()
	denylist.containsErr = errors.New("redis unavailable")
	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), denylist, nil, nil, nil)

	token := testAccessToken(t, priv, "jti-5", []string{"openid"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if received() != nil {
		t.Error("the upstream was called despite a denylist read error")
	}
}

// TestNewHandler_UpstreamFailureLeaksNoDetail is RS-20/T-17's own
// done-when: an upstream failure's response body contains no hostname or
// internal detail.
//
// Negative control: with gatewayErrorHandler's body temporarily changed
// to `fmt.Fprintf(w, "proxy error: %v", err)` (the naive, obvious
// implementation), this test failed -- the response body contained the
// literal unreachable address ("127.0.0.1:<port>"), Go's own transport
// error text embedding it verbatim. Verified by hand, restored before
// committing.
func TestNewHandler_UpstreamFailureLeaksNoDetail(t *testing.T) {
	priv := testRSAKeyPair(t)
	// A server that is immediately closed: its address is still a valid
	// URL, but nothing is listening, so the upstream round trip fails
	// with a real "connection refused" naming that exact address.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadAddr := dead.Listener.Addr().String()
	dead.Close()

	u, err := url.Parse("http://" + deadAddr)
	if err != nil {
		t.Fatalf("parse dead upstream URL: %v", err)
	}
	route := Route{PathPrefix: "/api", Upstream: u, Audience: testAudience}
	handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), nil, nil, nil)

	token := testAccessToken(t, priv, "jti-6", []string{"openid"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	body := rec.Body.String()
	if strings.Contains(body, deadAddr) {
		t.Errorf("response body leaked the upstream's own address: %q", body)
	}
	if body != "" {
		t.Errorf("response body = %q, want empty", body)
	}
}

// TestNewHandler_NoAutomaticRedirectFollowing is RS-20's other clause: an
// upstream redirect is forwarded to the client as-is, never followed by
// the gateway itself. No feasible single-line mutation of
// httputil.ReverseProxy reproduces "redirect followed" (that would
// require wrapping Transport in an http.Client with its own
// CheckRedirect, a structural change, not a removable line) -- this is
// asserted directly against net/http's own documented behavior
// (Transport.RoundTrip never follows redirects) rather than given a
// negative control.
func TestNewHandler_NoAutomaticRedirectFollowing(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://evil.example/other")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(upstream.Close)

	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), newFakeDenylist(), nil, nil, nil)
	token := testAccessToken(t, priv, "jti-7", []string{"openid"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (the redirect itself, not followed)", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != "http://evil.example/other" {
		t.Errorf("Location = %q, want it forwarded unchanged", got)
	}
}

// TestNewHandler_ResponseBodyTruncatedAtLimit is RS-21's response-size
// half: an upstream response larger than maxUpstreamResponseBytes is
// truncated, not copied to the client in full.
//
// Negative control: with the `ModifyResponse` field removed from
// NewHandler's *httputil.ReverseProxy, this test failed -- the full
// oversized body reached the client. Verified by hand, restored before
// committing.
func TestNewHandler_ResponseBodyTruncatedAtLimit(t *testing.T) {
	priv := testRSAKeyPair(t)
	const extra = 4096
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.CopyN(w, zeroReader{}, maxUpstreamResponseBytes+extra)
	}))
	t.Cleanup(upstream.Close)

	handler := NewHandler(testRoute(t, upstream), testValidator(t, priv), newFakeDenylist(), nil, nil, nil)
	token := testAccessToken(t, priv, "jti-8", []string{"openid"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if got := rec.Body.Len(); got != maxUpstreamResponseBytes {
		t.Errorf("response body = %d bytes, want exactly %d (truncated at the limit)", got, maxUpstreamResponseBytes)
	}
}

// zeroReader is an infinite source of zero bytes -- io.CopyN's own
// limit is what bounds the write, so this never needs to allocate the
// full body in memory to produce it.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestUpstreamTransport_AllTimeoutsSet is RS-21's upstream half of the
// issue's own third done-when ("server and upstream timeouts all set").
// The server half is cmd/usher/serve_test.go's own
// TestNewServer_AllTimeoutsSet.
//
// Negative control: with `ResponseHeaderTimeout` temporarily zeroed in
// newUpstreamTransport, this test failed. Verified by hand for each
// field in turn, restored before committing.
func TestUpstreamTransport_AllTimeoutsSet(t *testing.T) {
	transport := newUpstreamTransport()

	if upstreamDialer.Timeout == 0 {
		t.Error("upstreamDialer.Timeout is unset")
	}
	if transport.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout is unset")
	}
	if transport.ResponseHeaderTimeout == 0 {
		t.Error("ResponseHeaderTimeout is unset")
	}
	if transport.ExpectContinueTimeout == 0 {
		t.Error("ExpectContinueTimeout is unset")
	}
	if transport.IdleConnTimeout == 0 {
		t.Error("IdleConnTimeout is unset")
	}
	if maxUpstreamResponseBytes <= 0 {
		t.Error("maxUpstreamResponseBytes is not a positive limit")
	}
}

// TestValidateRoute_EmptyAudienceRefused is #41's own second done-when:
// a route without an audience refuses to start.
//
// Negative control: with the `route.Audience == ""` check removed from
// ValidateRoute, this test failed -- an audience-less route validated
// successfully. Verified by hand, restored before committing.
func TestValidateRoute_EmptyAudienceRefused(t *testing.T) {
	if err := ValidateRoute(Route{PathPrefix: "/api", Audience: ""}); err == nil {
		t.Fatal("ValidateRoute accepted a route with no audience")
	}
	if err := ValidateRoute(Route{PathPrefix: "/api", Audience: testAudience}); err != nil {
		t.Errorf("ValidateRoute rejected a route with a real audience: %v", err)
	}
}

// TestNewHandler_PanicsOnRouteWithoutAudience is the same property
// applied where it actually bites: NewHandler itself refuses to build a
// handler for a Route with no audience, rather than silently serving
// requests with the audience check skipped.
//
// Negative control: with the `ValidateRoute(route)` call removed from
// NewHandler, this test failed -- NewHandler returned a handler instead
// of panicking. Verified by hand, restored before committing.
func TestNewHandler_PanicsOnRouteWithoutAudience(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, _ := capturingUpstream(t, http.StatusOK)
	route := Route{PathPrefix: "/api", Upstream: mustParseURL(t, upstream.URL), Audience: ""}

	defer func() {
		if recover() == nil {
			t.Error("NewHandler did not panic on a route with no audience")
		}
	}()
	NewHandler(route, testValidator(t, priv), newFakeDenylist(), nil, nil, nil)
}

// fakeRoleLookup is this file's own stand-in for the real
// identity.UserStore-backed adapter cmd/usher builds — a map keyed by
// subject, so a test can assign testSubject whatever role (or lookup
// error) it needs without a real UserStore.
type fakeRoleLookup struct {
	roles map[string]string
	err   error
}

func (f fakeRoleLookup) RoleOf(_ context.Context, subject string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.roles[subject], nil
}

// TestNewHandler_PanicsOnAuthorizerWithoutPermission is RF-05's own
// "wiring mistake must be loud": a non-nil Authorizer with no
// route.Permission panics, the same property
// TestNewHandler_PanicsOnRouteWithoutAudience already proves for
// Audience.
//
// Negative control: with the `route.Permission == ""` check removed
// from NewHandler, this test failed -- NewHandler returned a handler
// instead of panicking. Verified by hand, restored before committing.
func TestNewHandler_PanicsOnAuthorizerWithoutPermission(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, _ := capturingUpstream(t, http.StatusOK)
	route := testRoute(t, upstream)
	route.Permission = ""

	defer func() {
		if recover() == nil {
			t.Error("NewHandler did not panic on a non-nil Authorizer with no route.Permission")
		}
	}()
	NewHandler(route, testValidator(t, priv), newFakeDenylist(), fakeRoleLookup{}, rbac.New(nil), nil)
}

// TestNewHandler_RBAC_RoleHasPermission_Allowed and the two tests after
// it are RF-05 itself: effective permission is the intersection of the
// token's own scope and the subject's role, computed for real now that
// #104's follow-up wires an Authorizer and RoleLookup through.
func TestNewHandler_RBAC_RoleHasPermission_Allowed(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	route := testRoute(t, upstream)
	route.Permission = "widgets:read"
	roles := fakeRoleLookup{roles: map[string]string{testSubject: "admin"}}
	authorizer := rbac.New(rbac.Permissions{"admin": {"widgets:read"}})
	handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), roles, authorizer, nil)

	token := testAccessToken(t, priv, "jti-rbac-1", []string{"widgets:read"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if received() == nil {
		t.Error("the upstream was never called despite scope ∩ role granting the permission")
	}
}

// Negative control: with the `authorizer.Allowed(...)` check (and its
// surrounding `if authorizer != nil` block) removed from NewHandler,
// this test failed -- a role with no matching permission still reached
// the upstream. Verified by hand, restored before committing.
func TestNewHandler_RBAC_RoleLacksPermission_Forbidden(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	route := testRoute(t, upstream)
	route.Permission = "widgets:read"
	roles := fakeRoleLookup{roles: map[string]string{testSubject: "guest"}}
	authorizer := rbac.New(rbac.Permissions{"admin": {"widgets:read"}})
	handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), roles, authorizer, nil)

	token := testAccessToken(t, priv, "jti-rbac-2", []string{"widgets:read"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if received() != nil {
		t.Error("the upstream was called despite a role with no matching permission")
	}
}

func TestNewHandler_RBAC_RoleLookupErrorFailsClosed(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	route := testRoute(t, upstream)
	route.Permission = "widgets:read"
	roles := fakeRoleLookup{err: errors.New("role store unavailable")}
	authorizer := rbac.New(rbac.Permissions{"admin": {"widgets:read"}})
	handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), roles, authorizer, nil)

	token := testAccessToken(t, priv, "jti-rbac-3", []string{"widgets:read"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (RNF-04: a lookup failure denies)", rec.Code, http.StatusUnauthorized)
	}
	if received() != nil {
		t.Error("the upstream was called despite a role-lookup failure")
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return u
}

// TestNewHandler_CrossAudienceTokenRefused is #41's own first done-when:
// a token issued for one resource server's audience is refused at a
// different route whose own audience names a different resource
// server, even though the token's signature, issuer and every other
// claim are genuinely valid.
func TestNewHandler_CrossAudienceTokenRefused(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstreamB, receivedB := capturingUpstream(t, http.StatusOK)
	routeB := testRouteWithAudience(t, upstreamB, testAudienceB)
	handler := NewHandler(routeB, testValidator(t, priv), newFakeDenylist(), nil, nil, nil)

	// Signed for RS-A's audience, presented at RS-B's own route.
	tokenForA := testAccessTokenForAudience(t, priv, "jti-cross", []string{"openid"}, testAudience)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+tokenForA, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (a token for a different resource server's audience)", rec.Code, http.StatusUnauthorized)
	}
	if receivedB() != nil {
		t.Error("RS-B's upstream was called with a token issued for RS-A's audience")
	}
}

// TestNewHandler_IDTokenRefused is #44's own gateway-side done-when: an
// id_token presented as a bearer credential gets 401, same as any other
// bearer credential whose shape is wrong. This is not a new protection --
// pkg/tokenvalidator's typ == "at+jwt" check (RS-08, #38/#40) already
// rejects anything whose JWS header says otherwise, before it ever looks
// at a claim -- this test only proves that existing, unchanged check also
// catches the real shape an id_token now takes. Audience is deliberately
// set to match the route's own (unlike TestNewHandler_CrossAudienceTokenRefused
// above, which isolates aud instead): with typ rejecting first, aud never
// gets reached regardless, so there's nothing left here to isolate.
func TestNewHandler_IDTokenRefused(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)
	route := testRoute(t, upstream)
	handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), nil, nil, nil)

	idToken := testIDToken(t, priv, testAudience)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+idToken, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (an id_token presented as a bearer credential)", rec.Code, http.StatusUnauthorized)
	}
	if received() != nil {
		t.Error("upstream was called with an id_token as the bearer credential")
	}
}

// TestNewHandler_WithoutAudienceCheckCrossAudienceTokenWouldBeAccepted
// is why TestValidateRoute_EmptyAudienceRefused and
// TestNewHandler_PanicsOnRouteWithoutAudience matter, made concrete:
// tokenvalidator.ValidateAccessToken treats an empty wantAudience as "no
// audience required," so a route that reached production with no
// audience at all -- which ValidateRoute and NewHandler's own panic
// exist specifically to make unreachable -- would accept the exact
// cross-RS token TestNewHandler_CrossAudienceTokenRefused proves is
// otherwise refused.
//
// This does not mutate production code: it drives the same
// *tokenvalidator.Validator the real pipeline uses directly, with the
// same empty-audience shape NewHandler's panic prevents from ever
// reaching it, to demonstrate the failure mode those guards close
// rather than merely assert that they exist.
func TestNewHandler_WithoutAudienceCheckCrossAudienceTokenWouldBeAccepted(t *testing.T) {
	priv := testRSAKeyPair(t)
	validator := testValidator(t, priv)
	tokenForA := testAccessTokenForAudience(t, priv, "jti-cross-2", []string{"openid"}, testAudience)

	if _, err := validator.ValidateAccessToken(context.Background(), tokenForA, ""); err != nil {
		t.Fatalf("a token valid for RS-A, checked with no required audience, was rejected: %v -- this was meant to demonstrate acceptance, not refusal", err)
	}
}

// TestNewHandler_OpenCircuitReturns503WithRetryAfter is ADR-0016's own
// rule 1 and #42's first done-when: an open circuit refuses the call
// without ever reaching the upstream, and responds 503 with
// Retry-After, never the bare 502 a genuine upstream failure gets (RNF-04:
// a breaker rejection is a handled, not a hidden, denial).
//
// Negative control: with the `errors.Is(err, bastion.ErrOpenState) ||
// ...` branch removed from NewHandler's ErrorHandler (falling through
// to gatewayErrorHandler unconditionally), this test failed -- status
// was 502, with no Retry-After header at all. Verified by hand,
// restored before committing.
func TestNewHandler_OpenCircuitReturns503WithRetryAfter(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)

	breaker, err := bastion.New("test-upstream-open")
	if err != nil {
		t.Fatalf("bastion.New: %v", err)
	}
	breaker.Trip(context.Background())

	route := testRoute(t, upstream)
	route.Breaker = breaker
	handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), nil, nil, nil)

	token := testAccessToken(t, priv, "jti-breaker-open", []string{"openid"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if rec.Code == http.StatusInternalServerError {
		t.Fatal("status = 500, want anything but -- ADR-0016 rule 1 forbids it specifically")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After header is missing")
	}
	if received() != nil {
		t.Error("the upstream was called despite an open circuit")
	}
}

// countingUpstream answers every request with status and a fixed body,
// counting how many requests actually reached it.
func countingUpstream(t *testing.T, status int) (srv *httptest.Server, hits func() int32) {
	t.Helper()
	var n atomic.Int32
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "from-upstream")
	}))
	t.Cleanup(srv.Close)
	return srv, n.Load
}

// TestNewHandler_UnhealthyUpstreamOpensBreaker is ADR-0016's amendment
// (#118): an upstream that is up but answering 502/503/504 counts as a
// failure, so after bastion's threshold (5 consecutive, the default the
// router uses) the circuit opens and the gateway stops forwarding. While
// the circuit was still closed, the client got the upstream's own answer,
// not a gateway-made one.
//
// Negative control: with breakerRoundTripper's upstreamUnhealthy check
// disabled (every RoundTrip result handed to bastion unchanged), this test
// failed for every status — request 6 still reached the upstream and came
// back with its own 502/503/504 and no Retry-After. Verified by hand,
// restored before committing.
func TestNewHandler_UnhealthyUpstreamOpensBreaker(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			priv := testRSAKeyPair(t)
			upstream, hits := countingUpstream(t, status)
			breaker, err := bastion.New("test-upstream-unhealthy")
			if err != nil {
				t.Fatalf("bastion.New: %v", err)
			}
			route := testRoute(t, upstream)
			route.Breaker = breaker
			handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), nil, nil, nil)
			token := testAccessToken(t, priv, "jti-unhealthy", []string{"openid"})

			for i := 1; i <= 5; i++ {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))
				if rec.Code != status || rec.Body.String() != "from-upstream" {
					t.Fatalf("request %d: got %d %q, want the upstream's own %d answer passed through", i, rec.Code, rec.Body.String(), status)
				}
				if rec.Header().Get("Retry-After") != "" {
					t.Fatalf("request %d carried Retry-After before the threshold was reached", i)
				}
			}

			for i := 6; i <= 10; i++ {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))
				if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
					t.Fatalf("request %d: got %d (Retry-After %q), want the open circuit's 503 with Retry-After", i, rec.Code, rec.Header().Get("Retry-After"))
				}
			}
			if got := hits(); got != 5 {
				t.Errorf("upstream was reached %d times, want 5 — the open circuit must stop forwarding", got)
			}
		})
	}
}

// TestNewHandler_Upstream500DoesNotOpenBreaker is the other half of the
// same amendment: a 500 is a request's own bug, not the dependency's
// health, and must keep flowing through rather than refusing everything.
func TestNewHandler_Upstream500DoesNotOpenBreaker(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, hits := countingUpstream(t, http.StatusInternalServerError)
	breaker, err := bastion.New("test-upstream-500")
	if err != nil {
		t.Fatalf("bastion.New: %v", err)
	}
	route := testRoute(t, upstream)
	route.Breaker = breaker
	handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), nil, nil, nil)
	token := testAccessToken(t, priv, "jti-500", []string{"openid"})

	for i := 1; i <= 10; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))
		if rec.Code != http.StatusInternalServerError || rec.Body.String() != "from-upstream" {
			t.Fatalf("request %d: got %d %q, want the upstream's own 500 passed through", i, rec.Code, rec.Body.String())
		}
	}
	if got := hits(); got != 10 {
		t.Errorf("upstream was reached %d times, want all 10", got)
	}
}

// TestNewHandler_BreakerRejectionDoesNotRetryOutboundCall is ADR-0016's
// own rule 2 at its actual source: bastion.Execute is attempted at most
// once per incoming request. This is what makes "the rate limiter runs
// once, on the way in" hold regardless of what wraps this handler --
// outer middleware (REQUIREMENTS §7.2's own rate limiter among it) runs
// exactly once per incoming HTTP request by net/http's own dispatch, and
// nothing inside this handler calls back into the breaker a second time
// for one request.
func TestNewHandler_BreakerRejectionDoesNotRetryOutboundCall(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, received := capturingUpstream(t, http.StatusOK)

	var rejects int32
	breaker, err := bastion.New("test-upstream-norety", bastion.WithHooks(bastion.Hooks{
		OnReject: func(context.Context, bastion.RejectEvent) { atomic.AddInt32(&rejects, 1) },
	}))
	if err != nil {
		t.Fatalf("bastion.New: %v", err)
	}
	breaker.Trip(context.Background())

	route := testRoute(t, upstream)
	route.Breaker = breaker
	handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), nil, nil, nil)

	token := testAccessToken(t, priv, "jti-breaker-noretry", []string{"openid"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if got := atomic.LoadInt32(&rejects); got != 1 {
		t.Errorf("breaker OnReject fired %d times for one incoming request, want exactly 1", got)
	}
	if received() != nil {
		t.Error("the upstream was called despite an open circuit")
	}
}

// TestNewHandler_BreakerRejectionLeavesOuterLimiterChargedOnce is #42's
// own second done-when, literally: a counting fake standing in for
// moat/ratelimit.Limiter's own middleware (REQUIREMENTS §7.2's outer
// rate-limit layer), wrapped around NewHandler's result exactly as the
// real chain would. One incoming request, breaker open, must charge
// that outer layer exactly once -- never zero (bypassed) and never more
// than one (re-entered by something inside the handler).
func TestNewHandler_BreakerRejectionLeavesOuterLimiterChargedOnce(t *testing.T) {
	priv := testRSAKeyPair(t)
	upstream, _ := capturingUpstream(t, http.StatusOK)

	breaker, err := bastion.New("test-upstream-limiter")
	if err != nil {
		t.Fatalf("bastion.New: %v", err)
	}
	breaker.Trip(context.Background())

	route := testRoute(t, upstream)
	route.Breaker = breaker
	handler := NewHandler(route, testValidator(t, priv), newFakeDenylist(), nil, nil, nil)

	var limiterCalls int32
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&limiterCalls, 1)
		handler.ServeHTTP(w, r)
	})

	token := testAccessToken(t, priv, "jti-breaker-limiter", []string{"openid"})
	rec := httptest.NewRecorder()
	outer.ServeHTTP(rec, proxyRequest("Bearer "+token, nil))

	if got := atomic.LoadInt32(&limiterCalls); got != 1 {
		t.Errorf("the outer rate-limiter stand-in was invoked %d times for one incoming request, want exactly 1 -- a breaker rejection must never re-enter it", got)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}
