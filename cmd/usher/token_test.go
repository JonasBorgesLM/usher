package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/keys"
	"github.com/JonasBorgesLM/usher/internal/oauth"
)

const (
	testTokenCode     = "code-1"
	testVerifier      = "a-real-pkce-verifier-with-enough-entropy-0123456789"
	testOtherClientID = "other-client"
)

// testCodeChallenge is BASE64URL(SHA256(testVerifier)) -- the S256
// challenge a real /authorize request would have stored for this
// verifier.
func testCodeChallenge() string {
	sum := sha256.Sum256([]byte(testVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// testKeyFileMeta mirrors internal/keys's own unexported keyMetadata
// shape -- duplicated here because it is unexported to that package, the
// same reasoning router_test.go's own fakeSessionStore comment already
// gives for its small duplications.
type testKeyFileMeta struct {
	KID       string    `json:"kid"`
	Algorithm string    `json:"algorithm"`
	PublishAt time.Time `json:"publish_at"`
	SignFrom  time.Time `json:"sign_from"`
	RetireAt  time.Time `json:"retire_at"`
}

// testKeyset builds a one-key RS256 Keyset already publishing and signing
// as of now -- generous enough that no window check in keys.Load rejects
// it, the same shape internal/keys/keys_test.go uses for its own generous
// defaults. now must be the same fixed clock routerDeps.Now returns
// (testDeps's own time.Date(2026, 1, 1, ...)), not real wall-clock time:
// keys.Keyset.Signing is looked up against deps.Now(), not time.Now().
func testKeyset(t *testing.T, now time.Time) *keys.Keyset {
	t.Helper()
	dir := t.TempDir()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	meta := testKeyFileMeta{
		KID: "test-key", Algorithm: "RS256",
		PublishAt: now.Add(-2 * time.Hour), SignFrom: now.Add(-time.Hour), RetireAt: now.AddDate(1, 0, 0),
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal key metadata: %v", err)
	}
	if writeErr := os.WriteFile(filepath.Join(dir, "test-key.json"), metaBytes, 0o600); writeErr != nil {
		t.Fatalf("write key metadata: %v", writeErr)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if writeErr := os.WriteFile(filepath.Join(dir, "test-key.pem"), pemBytes, 0o600); writeErr != nil {
		t.Fatalf("write key PEM: %v", writeErr)
	}

	ks, err := keys.Load(dir, 30*time.Second, 5*time.Minute, 10*time.Minute, nil)
	if err != nil {
		t.Fatalf("keys.Load: %v", err)
	}
	return ks
}

func tokenDeps(t *testing.T, clients ...identity.Client) routerDeps {
	t.Helper()
	deps := testDeps(t)
	deps.Clients = clients
	deps.Keyset = testKeyset(t, deps.Now())
	deps.Families = newFakeFamilyStore()
	deps.RefreshIdleTTL = 24 * time.Hour
	deps.RefreshAbsoluteTTL = 7 * 24 * time.Hour
	return deps
}

// confidentialTestClient is testClient() (authorize_test.go) made
// confidential, with secret's SHA-256 as its registered hash (RS-16).
func confidentialTestClient(secret string) identity.Client {
	c := testClient()
	c.Confidential = true
	sum := sha256.Sum256([]byte(secret))
	c.SecretHash = hex.EncodeToString(sum[:])
	return c
}

// seedCode saves a Code directly into deps.Codes, simulating "a client
// already completed /authorize -> login -> consent" (#30's own
// prerequisite, tested separately in consent_test.go) without going
// through that whole flow.
func seedCode(t *testing.T, deps routerDeps, value, clientID, redirectURI string, scope []string) {
	t.Helper()
	code := oauth.Code{
		Value: value, ClientID: clientID, RedirectURI: redirectURI,
		CodeChallenge: testCodeChallenge(), Scope: scope, Subject: testSubject,
		ExpiresAt: deps.Now().Add(time.Minute),
	}
	if err := deps.Codes.Save(context.Background(), code); err != nil {
		t.Fatalf("seed code: %v", err)
	}
}

// validTokenForm is the known-good baseline every test below mutates
// exactly one value away from, the same shape authorize_test.go's own
// validAuthorizeQuery() uses.
func validTokenForm() url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {testTokenCode},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {testVerifier},
		"client_id":     {testClientID},
	}
}

func postToken(form url.Values, basicUser, basicPass string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://usher.test/token", strings.NewReader(form.Encode()))
	req.Host = "usher.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" || basicPass != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	return req
}

func decodeTokenSuccess(t *testing.T, rec *httptest.ResponseRecorder) tokenSuccessBody {
	t.Helper()
	var body tokenSuccessBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode token success body: %v, raw: %s", err, rec.Body.String())
	}
	return body
}

// TestToken_AuthorizationCode_GoldenPath is RF-03's own done-when: a
// correct authorization_code exchange issues an access token with the
// full RS-07 claim set, typ: at+jwt (RS-08, RFC 9068), and aud = the
// client's own configured audiences -- no refresh_token, no id_token
// (M2's stated scope).
//
// Negative control: with the `hdrs.Set(jws.TypeKey, "at+jwt")` call
// removed from signAccessToken, this test failed -- the JWS header
// carried no typ at all. Verified by hand, restored before committing.
func TestToken_AuthorizationCode_GoldenPath(t *testing.T) {
	client := testClient()
	client.Audiences = []string{"https://rs.example"}
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid", "profile"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token golden path = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeTokenSuccess(t, rec)
	if body.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", body.TokenType)
	}
	if body.AccessToken == "" {
		t.Fatal("access_token is empty")
	}
	if body.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", body.ExpiresIn)
	}
	if body.Scope != "openid profile" {
		t.Errorf("scope = %q, want %q", body.Scope, "openid profile")
	}
	// tokenSuccessBody itself has no refresh_token/id_token field at all
	// (M2's stated scope) -- there is nothing further to assert here.
	if strings.Contains(rec.Body.String(), "refresh_token") || strings.Contains(rec.Body.String(), "id_token") {
		t.Errorf("response body unexpectedly mentions refresh_token/id_token: %s", rec.Body.String())
	}

	key := deps.Keyset.Published(deps.Now())[0]
	pub := key.Private.Public()

	msg, err := jws.Parse([]byte(body.AccessToken))
	if err != nil {
		t.Fatalf("jws.Parse: %v", err)
	}
	typ, ok := msg.Signatures()[0].ProtectedHeaders().Type()
	if !ok || typ != "at+jwt" {
		t.Errorf("JWS typ header = %q, ok=%v, want %q (RFC 9068, RS-08)", typ, ok, "at+jwt")
	}

	parsed, err := jwt.Parse([]byte(body.AccessToken), jwt.WithKey(jwa.RS256(), pub), jwt.WithValidate(false))
	if err != nil {
		t.Fatalf("parse/verify access token: %v", err)
	}
	if iss, _ := parsed.Issuer(); iss != deps.Issuer {
		t.Errorf("iss = %q, want %q", iss, deps.Issuer)
	}
	if sub, _ := parsed.Subject(); sub != testSubject {
		t.Errorf("sub = %q, want %q", sub, testSubject)
	}
	if aud, _ := parsed.Audience(); len(aud) != 1 || aud[0] != "https://rs.example" {
		t.Errorf("aud = %v, want [https://rs.example]", aud)
	}
	if _, ok := parsed.Expiration(); !ok {
		t.Error("exp is missing")
	}
	if _, ok := parsed.NotBefore(); !ok {
		t.Error("nbf is missing")
	}
	if _, ok := parsed.IssuedAt(); !ok {
		t.Error("iat is missing")
	}
	if jti, ok := parsed.JwtID(); !ok || jti == "" {
		t.Error("jti is missing or empty")
	}
	clientID, err := jwt.Get[string](parsed, "client_id")
	if err != nil || clientID != testClientID {
		t.Errorf("client_id = %q, err=%v, want %q", clientID, err, testClientID)
	}
}

// TestToken_WrongVerifierRedirectURIOrClient_AllYieldIdenticalInvalidGrant
// is the issue's own first done-when: three distinct causes -- a wrong
// code_verifier, a wrong redirect_uri, and redemption by a different
// (but itself valid) client than the one the code was issued to -- all
// collapse to the exact same invalid_grant body (RS-25). This exercises
// oauth.ConsumeCode (#29) through the HTTP layer, not its own unit tests
// again.
//
// No separate negative control was run for this test: the ambiguity is
// ConsumeCode's own property, and ConsumeCode has nothing left in it to
// differentiate these three causes with -- it already collapses them to
// one sentinel error before this handler ever sees them (#29's own
// negative controls, internal/oauth/consume_test.go, are what proved that
// collapse). This handler's only remaining way to reintroduce a
// distinction would be inventing one from scratch (passing err.Error()
// through, say), which is not a protection this file removes and
// restores -- there is no such code path here to break.
func TestToken_WrongVerifierRedirectURIOrClient_AllYieldIdenticalInvalidGrant(t *testing.T) {
	owner := testClient()
	other := testClient()
	other.ID = testOtherClientID
	other.RedirectURIs = []string{"https://other.example/callback"}
	deps := tokenDeps(t, owner, other)
	mux := newRouter(deps)

	cases := map[string]url.Values{
		"wrong verifier": func() url.Values {
			f := validTokenForm()
			f.Set("code_verifier", "the-wrong-verifier-the-wrong-verifier")
			return f
		}(),
		"wrong redirect_uri": func() url.Values {
			f := validTokenForm()
			f.Set("redirect_uri", "https://attacker.example/callback")
			return f
		}(),
		"wrong client": func() url.Values {
			f := validTokenForm()
			f.Set("client_id", testOtherClientID)
			return f
		}(),
	}

	var bodies []string
	for name, form := range cases {
		seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, postToken(form, "", ""))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want %d, body: %s", name, rec.Code, http.StatusBadRequest, rec.Body.String())
		}
		bodies = append(bodies, rec.Body.String())
	}

	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("invalid_grant bodies differ: %q vs %q", bodies[0], bodies[i])
		}
	}
	if bodies[0] != `{"error":"invalid_grant"}`+"\n" {
		t.Errorf("invalid_grant body = %q, want the fixed, description-free shape", bodies[0])
	}
}

// TestToken_NoStoreOnSuccessAndError is RS-26, on both a success and an
// error response -- the fixed order (chain.go) puts no-store outermost
// specifically so a rejection still carries it.
//
// Negative control: with tokenGroup.noStore changed to false in
// chain.go, this test failed on both sub-cases -- Cache-Control was
// absent. Verified by hand, restored before committing.
func TestToken_NoStoreOnSuccessAndError(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("golden path = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("success Cache-Control = %q, want %q", got, "no-store")
	}

	badForm := validTokenForm()
	badForm.Set("code_verifier", "wrong")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, postToken(badForm, "", ""))
	if got := rec2.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("error Cache-Control = %q, want %q", got, "no-store")
	}
}

// TestToken_ConfidentialClientWrongSecretIsInvalidClient is RS-16: a
// confidential client presenting a wrong (or absent) secret is refused,
// distinctly from invalid_grant, with no CSRF requirement on the route
// (checked implicitly -- this request carries no CSRF token at all and
// still reaches the handler).
//
// Negative control: with the `client.Confidential &&
// !client.AuthenticateSecret(secret)` check in authenticateClient
// replaced with `false` (never rejecting), this test failed -- a wrong
// secret authenticated successfully and the request proceeded to
// invalid_grant (wrong code_verifier never checked, since the request
// below passes a valid one) returning 200 instead of 401. Verified by
// hand, restored before committing.
func TestToken_ConfidentialClientWrongSecretIsInvalidClient(t *testing.T) {
	client := confidentialTestClient("correct-secret")
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), testClientID, "wrong-secret"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong client secret = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"invalid_client"}`+"\n" {
		t.Errorf("body = %q, want the fixed, description-free invalid_client shape", rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Basic") {
		t.Errorf("WWW-Authenticate = %q, want it to name Basic", got)
	}
}

// TestToken_ConfidentialClientCorrectSecretViaBasicAuth proves the
// success half of RS-16's Basic path: the right secret, over
// Authorization: Basic, authenticates.
func TestToken_ConfidentialClientCorrectSecretViaBasicAuth(t *testing.T) {
	client := confidentialTestClient("correct-secret")
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	form := validTokenForm()
	form.Del("client_id") // Basic carries it; present in both is #2.3.1's ambiguity

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(form, testClientID, "correct-secret"))

	if rec.Code != http.StatusOK {
		t.Fatalf("correct secret over Basic = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestToken_PublicClientNeedsNoSecret confirms RS-16's other half: a
// public client authenticates with no secret at all -- PKCE alone stands
// in for one.
func TestToken_PublicClientNeedsNoSecret(t *testing.T) {
	client := testClient() // Confidential: false
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("public client with no secret = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestToken_UnsupportedGrantType is RFC 6749 §5.2's fixed code for a
// grant_type this project does not implement at all (client_credentials
// is M8).
func TestToken_UnsupportedGrantType(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	mux := newRouter(deps)

	form := validTokenForm()
	form.Set("grant_type", "client_credentials")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(form, "", ""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported grant_type = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if rec.Body.String() != `{"error":"unsupported_grant_type"}`+"\n" {
		t.Errorf("body = %q, want the fixed unsupported_grant_type shape", rec.Body.String())
	}
}

// TestToken_AccessTokenNeverLogged is the issue's own third done-when
// (RS-24): a successful exchange's access token, the code it consumed,
// and the code_verifier it checked never appear in a log line.
//
// Negative control: with a temporary
// `h.logger.InfoContext(r.Context(), "token: issued", "access_token",
// string(accessToken))` added to token.go's success path, this test
// failed -- the captured log output contained the access token in full.
// Verified by hand, removed before committing.
func TestToken_AccessTokenNeverLogged(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	var logBuf bytes.Buffer
	deps.Logger = newProductionLogger(&logBuf)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("golden path = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeTokenSuccess(t, rec)
	if body.AccessToken == "" {
		t.Fatal("access_token is empty")
	}

	logged := logBuf.String()
	if strings.Contains(logged, body.AccessToken) {
		t.Errorf("the access token appeared in a log line: %s", logged)
	}
	if strings.Contains(logged, testTokenCode) {
		t.Errorf("the authorization code appeared in a log line: %s", logged)
	}
	if strings.Contains(logged, testVerifier) {
		t.Errorf("the code_verifier appeared in a log line: %s", logged)
	}
}

// TestToken_SuccessResponseCarriesNoLocation is RS-24's other half: the
// token never travels by redirect -- the success response is a plain
// 200 with a JSON body, never a 3xx with a Location.
func TestToken_SuccessResponseCarriesNoLocation(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))

	if got := rec.Header().Get("Location"); got != "" {
		t.Errorf("token success response carries a Location header: %q", got)
	}
}
