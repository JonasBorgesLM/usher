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
	"slices"
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
	seedCodeWithNonce(t, deps, value, clientID, redirectURI, scope, "")
}

// seedCodeWithNonce is seedCode with the nonce exposed, for #44's own
// done-when that a nonce present on the code is echoed, unchanged, in
// the id_token (RS-30).
func seedCodeWithNonce(t *testing.T, deps routerDeps, value, clientID, redirectURI string, scope []string, nonce string) {
	t.Helper()
	code := oauth.Code{
		Value: value, ClientID: clientID, RedirectURI: redirectURI,
		CodeChallenge: testCodeChallenge(), Scope: scope, Subject: testSubject,
		Nonce: nonce, ExpiresAt: deps.Now().Add(time.Minute),
	}
	if err := deps.Codes.Save(context.Background(), code); err != nil {
		t.Fatalf("seed code: %v", err)
	}
}

// seedCodeWithAuthTime is seedCode with AuthTime exposed, for #47's own
// done-when that a Code carrying one echoes it, unchanged, as the
// id_token's own auth_time claim (RF-11).
func seedCodeWithAuthTime(t *testing.T, deps routerDeps, value, clientID, redirectURI string, scope []string, authTime time.Time) {
	t.Helper()
	code := oauth.Code{
		Value: value, ClientID: clientID, RedirectURI: redirectURI,
		CodeChallenge: testCodeChallenge(), Scope: scope, Subject: testSubject,
		AuthTime: authTime, ExpiresAt: deps.Now().Add(time.Minute),
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
// client's own configured audiences -- no refresh_token (this client's
// own grant_types never include it). The scope requested here
// (openid profile) also makes this the golden path for id_token
// issuance (#44): see the id_token assertions below, added once that
// became real -- this test's own comment used to say "no id_token
// (M2's stated scope)", which M7 supersedes directly.
//
// Negative control: with the `hdrs.Set(jws.TypeKey, "at+jwt")` call
// removed from signJWT, this test failed -- the JWS header carried no
// typ at all. Verified by hand, restored before committing.
//
// Second negative control (#45, RS-08): with the `slices.Contains(scope,
// "openid")` gate in issueAccessToken short-circuited to always-false,
// this test's own aud assertion failed -- the access token carried only
// the resource-server audience, missing the userinfo one an
// openid-scoped request must also get. TestUserinfo_GoldenPath failed
// alongside it, for the same reason. Verified by hand, restored before
// committing.
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
	// This client's grant_types never include refresh_token (testClient(),
	// authorize_test.go) -- that half of the old assertion still holds.
	if strings.Contains(rec.Body.String(), "refresh_token") {
		t.Errorf("response body unexpectedly mentions refresh_token: %s", rec.Body.String())
	}
	if body.IDToken == "" {
		t.Fatal("id_token is empty, want one since scope includes openid (RF-03, RF-11)")
	}

	key := deps.Keyset.Published(deps.Now())[0]
	pub := key.Private.Public()

	msg, err := jws.Parse([]byte(body.AccessToken))
	if err != nil {
		t.Fatalf("jws.Parse: %v", err)
	}
	typ, typOK := msg.Signatures()[0].ProtectedHeaders().Type()
	if !typOK || typ != "at+jwt" {
		t.Errorf("JWS typ header = %q, ok=%v, want %q (RFC 9068, RS-08)", typ, typOK, "at+jwt")
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
	// RS-08: an openid-scoped request's access token carries usher's own
	// userinfo audience alongside the resource server's, never in place
	// of it (#45).
	wantAud := []string{"https://rs.example", userinfoAudience(deps.Issuer)}
	if aud, _ := parsed.Audience(); !slices.Equal(aud, wantAud) {
		t.Errorf("aud = %v, want %v", aud, wantAud)
	}
	if _, expOK := parsed.Expiration(); !expOK {
		t.Error("exp is missing")
	}
	if _, nbfOK := parsed.NotBefore(); !nbfOK {
		t.Error("nbf is missing")
	}
	if _, iatOK := parsed.IssuedAt(); !iatOK {
		t.Error("iat is missing")
	}
	if jti, jtiOK := parsed.JwtID(); !jtiOK || jti == "" {
		t.Error("jti is missing or empty")
	}
	clientID, err := jwt.Get[string](parsed, "client_id")
	if err != nil || clientID != testClientID {
		t.Errorf("client_id = %q, err=%v, want %q", clientID, err, testClientID)
	}

	idMsg, err := jws.Parse([]byte(body.IDToken))
	if err != nil {
		t.Fatalf("jws.Parse(id_token): %v", err)
	}
	idTyp, idTypOK := idMsg.Signatures()[0].ProtectedHeaders().Type()
	if !idTypOK || idTyp != "id_token" {
		t.Errorf("id_token JWS typ header = %q, ok=%v, want %q", idTyp, idTypOK, "id_token")
	}
	idParsed, err := jwt.Parse([]byte(body.IDToken), jwt.WithKey(jwa.RS256(), pub), jwt.WithValidate(false))
	if err != nil {
		t.Fatalf("parse/verify id_token: %v", err)
	}
	if iss, _ := idParsed.Issuer(); iss != deps.Issuer {
		t.Errorf("id_token iss = %q, want %q", iss, deps.Issuer)
	}
	if sub, _ := idParsed.Subject(); sub != testSubject {
		t.Errorf("id_token sub = %q, want %q", sub, testSubject)
	}
	// aud is the client alone (RS-08) -- never client.Audiences. What
	// actually gets this id_token rejected at the gateway is its JWS typ
	// header ("id_token", never "at+jwt" -- see proxy_test.go's own
	// addition for #44), checked before aud ever comes into it.
	if aud, _ := idParsed.Audience(); len(aud) != 1 || aud[0] != testClientID {
		t.Errorf("id_token aud = %v, want [%s]", aud, testClientID)
	}
	if _, idExpOK := idParsed.Expiration(); !idExpOK {
		t.Error("id_token exp is missing")
	}
	if _, idIatOK := idParsed.IssuedAt(); !idIatOK {
		t.Error("id_token iat is missing")
	}
	// This test's own seedCode call carries no nonce -- omitted, not
	// empty-string (RS-30). See TestToken_AuthorizationCode_NonceEchoed
	// for the round-trip case.
	if nonce, err := jwt.Get[string](idParsed, "nonce"); err == nil {
		t.Errorf("id_token nonce = %q, want absent (no nonce on this code)", nonce)
	}
	// Same reasoning for auth_time (RF-11, #47): seedCode's own Code
	// carries a zero AuthTime, which must stay absent, never a
	// zero-looking Unix epoch 0 claim. See
	// TestToken_AuthorizationCode_AuthTimeEchoed for the round-trip case.
	if authTime, err := jwt.Get[int64](idParsed, "auth_time"); err == nil {
		t.Errorf("id_token auth_time = %v, want absent (no auth_time on this code)", authTime)
	}
}

// TestToken_AuthorizationCode_NonceEchoed is #44's own done-when: a
// nonce bound to the code at /authorize (RF-11) comes back unchanged in
// the id_token (RS-30) -- never regenerated, never dropped.
//
// Negative control: with `Nonce: nonce` removed from issueIDToken's
// idTokenClaims construction, this test failed -- the id_token carried
// no nonce claim at all while this test's own code had one. Verified by
// hand, restored before committing.
func TestToken_AuthorizationCode_NonceEchoed(t *testing.T) {
	const wantNonce = "test-nonce-7f3a"
	client := testClient()
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCodeWithNonce(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"}, wantNonce)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeTokenSuccess(t, rec)
	if body.IDToken == "" {
		t.Fatal("id_token is empty")
	}

	key := deps.Keyset.Published(deps.Now())[0]
	pub := key.Private.Public()
	parsed, err := jwt.Parse([]byte(body.IDToken), jwt.WithKey(jwa.RS256(), pub), jwt.WithValidate(false))
	if err != nil {
		t.Fatalf("parse/verify id_token: %v", err)
	}
	nonce, err := jwt.Get[string](parsed, "nonce")
	if err != nil || nonce != wantNonce {
		t.Errorf("id_token nonce = %q, err=%v, want %q", nonce, err, wantNonce)
	}
}

// TestToken_AuthorizationCode_AuthTimeEchoed is #47's own done-when: a
// Code carrying an AuthTime (set by /login, fresh or reused -- consent.go's
// own completeConsent, not this file) comes back as the id_token's
// auth_time claim, unchanged (RF-11).
//
// Negative control: with the `if !authTime.IsZero() { claims.AuthTime =
// ... }` block removed from issueIDToken, this test failed -- auth_time
// was absent from an id_token whose Code genuinely carried one. Verified
// by hand, restored before committing.
func TestToken_AuthorizationCode_AuthTimeEchoed(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	wantAuthTime := deps.Now().Add(-90 * time.Second)
	seedCodeWithAuthTime(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"}, wantAuthTime)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeTokenSuccess(t, rec)
	if body.IDToken == "" {
		t.Fatal("id_token is empty")
	}

	key := deps.Keyset.Published(deps.Now())[0]
	pub := key.Private.Public()
	parsed, err := jwt.Parse([]byte(body.IDToken), jwt.WithKey(jwa.RS256(), pub), jwt.WithValidate(false))
	if err != nil {
		t.Fatalf("parse/verify id_token: %v", err)
	}
	authTime, err := jwt.Get[float64](parsed, "auth_time")
	if err != nil || int64(authTime) != wantAuthTime.Unix() {
		t.Errorf("id_token auth_time = %v, err=%v, want %d", authTime, err, wantAuthTime.Unix())
	}
}

// TestToken_RefreshToken_NoIDTokenReissued documents a deliberate choice,
// not an oversight: OIDC Core leaves re-issuing id_token on refresh
// optional, and nothing in REQUIREMENTS.md or the threat model asks for
// it, so handleRefreshToken passes "" unconditionally rather than
// calling issueIDToken a second time.
func TestToken_RefreshToken_NoIDTokenReissued(t *testing.T) {
	client := testClient()
	client.GrantTypes = []string{"authorization_code", "refresh_token"}
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token (authorization_code) = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	issued := decodeTokenSuccess(t, rec)
	if issued.RefreshToken == "" {
		t.Fatal("refresh_token is empty, want one since client.GrantTypes includes it")
	}

	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {issued.RefreshToken},
		"client_id":     {testClientID},
	}
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, postToken(refreshForm, "", ""))
	if rec2.Code != http.StatusOK {
		t.Fatalf("POST /token (refresh_token) = %d, want %d, body: %s", rec2.Code, http.StatusOK, rec2.Body.String())
	}
	refreshed := decodeTokenSuccess(t, rec2)
	if refreshed.IDToken != "" {
		t.Errorf("id_token = %q, want empty on refresh_token grant", refreshed.IDToken)
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

// TestToken_ConfidentialClientCorrectSecretViaPostBody backs discovery
// .go's own token_endpoint_auth_methods_supported claim that
// "client_secret_post" is a real, working option (#46), not just Basic
// auth -- authenticateClient's own `postSecret :=
// r.PostForm.Get("client_secret")` path, exercised directly rather than
// only read from the source.
func TestToken_ConfidentialClientCorrectSecretViaPostBody(t *testing.T) {
	client := confidentialTestClient("correct-secret")
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	form := validTokenForm()
	form.Set("client_secret", "correct-secret")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(form, "", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("correct secret over the POST body = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
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
	// password (ROPC): dropped from OAuth 2.1 before this project
	// started (REQUIREMENTS §3.1), never a candidate -- client_credentials
	// used to be this test's own example, until #49 made it real.
	form.Set("grant_type", "password")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(form, "", ""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported grant_type = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if rec.Body.String() != `{"error":"unsupported_grant_type"}`+"\n" {
		t.Errorf("body = %q, want the fixed unsupported_grant_type shape", rec.Body.String())
	}
}

// clientCredentialsTestClient is confidentialTestClient registered for
// the grant itself -- testClient()'s own GrantTypes is
// ["authorization_code"] only, and #49's own second done-when (a client
// not registered for client_credentials gets unauthorized_client) needs
// a fixture that genuinely has it, not one missing it by omission.
func clientCredentialsTestClient(secret string) identity.Client {
	c := confidentialTestClient(secret)
	c.GrantTypes = []string{"client_credentials"}
	c.Scopes = []string{"read", "write"}
	c.Audiences = []string{"https://rs.example"}
	return c
}

// clientCredentialsForm carries no client_id: every caller below
// authenticates over Basic auth instead (postToken's own clientID/secret
// params), the same "Basic carries it; present in both is #2.3.1's
// ambiguity" reasoning confidentialTestClient's own Basic-auth test
// already follows -- except the public-client test, which has no secret
// to put there and sets client_id on the form itself.
func clientCredentialsForm(scope string) url.Values {
	form := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	return form
}

// TestToken_ClientCredentials_GoldenPath is #49's own done-when made
// concrete: a confidential client registered for the grant gets an
// access token for itself -- sub = client.ID, aud = client.Audiences,
// scope narrowed to what was actually requested -- with neither a
// refresh_token nor an id_token in the response.
func TestToken_ClientCredentials_GoldenPath(t *testing.T) {
	client := clientCredentialsTestClient("correct-secret")
	deps := tokenDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(clientCredentialsForm("read"), testClientID, "correct-secret"))

	if rec.Code != http.StatusOK {
		t.Fatalf("client_credentials golden path = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeTokenSuccess(t, rec)
	if body.Scope != "read" {
		t.Errorf("scope = %q, want %q", body.Scope, "read")
	}
	if body.RefreshToken != "" {
		t.Errorf("refresh_token = %q, want empty", body.RefreshToken)
	}
	if body.IDToken != "" {
		t.Errorf("id_token = %q, want empty", body.IDToken)
	}

	key := deps.Keyset.Published(deps.Now())[0]
	pub := key.Private.Public()
	parsed, err := jwt.Parse([]byte(body.AccessToken), jwt.WithKey(jwa.RS256(), pub), jwt.WithValidate(false))
	if err != nil {
		t.Fatalf("parse/verify access token: %v", err)
	}
	if sub, _ := parsed.Subject(); sub != testClientID {
		t.Errorf("sub = %q, want the client's own id %q", sub, testClientID)
	}
	if aud, _ := parsed.Audience(); len(aud) != 1 || aud[0] != "https://rs.example" {
		t.Errorf("aud = %v, want [https://rs.example]", aud)
	}
}

// TestToken_ClientCredentials_PublicClientRefused is #49's own first
// done-when: a public client has no proof of possession for this grant
// (no PKCE, no secret) and is refused outright.
//
// Negative control: with the `!client.Confidential` check removed from
// handleClientCredentials, this test failed -- the public client's
// request succeeded with a real access token. Verified by hand, restored
// before committing.
func TestToken_ClientCredentials_PublicClientRefused(t *testing.T) {
	client := clientCredentialsTestClient("unused")
	client.Confidential = false
	client.SecretHash = ""
	deps := tokenDeps(t, client)
	mux := newRouter(deps)

	form := clientCredentialsForm("")
	form.Set("client_id", testClientID) // no secret to carry it over Basic auth instead
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(form, "", ""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("public client via client_credentials = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"unauthorized_client"}`+"\n" {
		t.Errorf("body = %q, want the fixed unauthorized_client shape", rec.Body.String())
	}
}

// TestToken_ClientCredentials_NotRegisteredForGrantRefused is the same
// refusal for a confidential client that is simply not registered for
// this grant -- being confidential is necessary, not sufficient.
//
// Negative control: with the `!slices.Contains(client.GrantTypes,
// "client_credentials")` check removed, this test failed -- a client
// whose own registration never named this grant got a token anyway.
// Verified by hand, restored before committing.
func TestToken_ClientCredentials_NotRegisteredForGrantRefused(t *testing.T) {
	client := confidentialTestClient("correct-secret") // GrantTypes: ["authorization_code"] only
	deps := tokenDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(clientCredentialsForm(""), testClientID, "correct-secret"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unregistered grant = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"unauthorized_client"}`+"\n" {
		t.Errorf("body = %q, want the fixed unauthorized_client shape", rec.Body.String())
	}
}

// TestToken_ClientCredentials_ScopeExceedingRegistrationRejected is
// #49's own "scopes limited to the client's registration": a scope the
// client was never registered for is invalid_scope, the same check
// /authorize already applies to the authorization_code grant.
//
// Negative control: with the `scopeSubset` call removed from
// handleClientCredentials (the requested scope used unchecked), this
// test failed -- a scope this client was never registered for was
// granted anyway. Verified by hand, restored before committing.
func TestToken_ClientCredentials_ScopeExceedingRegistrationRejected(t *testing.T) {
	client := clientCredentialsTestClient("correct-secret") // Scopes: ["read", "write"]
	deps := tokenDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(clientCredentialsForm("admin"), testClientID, "correct-secret"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unregistered scope = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"invalid_scope"}`+"\n" {
		t.Errorf("body = %q, want the fixed invalid_scope shape", rec.Body.String())
	}
}

// TestToken_ClientCredentials_NoIDTokenEvenWithOpenIDScope documents
// handleClientCredentials's own choice explicitly: this grant never
// calls issueIDToken, regardless of what the client's registered scope
// allows -- there is no user here for an id_token to describe.
func TestToken_ClientCredentials_NoIDTokenEvenWithOpenIDScope(t *testing.T) {
	client := clientCredentialsTestClient("correct-secret")
	client.Scopes = append(client.Scopes, "openid")
	deps := tokenDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(clientCredentialsForm("openid"), testClientID, "correct-secret"))

	if rec.Code != http.StatusOK {
		t.Fatalf("client_credentials with openid scope = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeTokenSuccess(t, rec)
	if body.IDToken != "" {
		t.Errorf("id_token = %q, want empty -- client_credentials has no user to describe one", body.IDToken)
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
