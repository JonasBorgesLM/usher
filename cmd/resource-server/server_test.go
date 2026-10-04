package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/JonasBorgesLM/moat/realip"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

const (
	testKID      = "test-key"
	testIssuer   = "https://usher.test"
	testAudience = "https://resource-server.test"
	testClientID = "client-1"
	testSubject  = "alice"
)

// fakeKeySource is a minimal tokenvalidator.KeySource -- this file's own
// tests are about widgetsHandler's orchestration, not JWKS resolution,
// which pkg/tokenvalidator's own tests already cover. Duplicated from
// internal/proxy's own test fixture of the same name and shape: this
// binary cannot import internal/, and internal/proxy cannot be imported
// from here either way (it is a different module boundary entirely).
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
// duplicated for the same reason internal/proxy's own test fixture
// duplicates it: neither this binary nor pkg/ may import cmd/usher or
// internal/ (ADR-0001).
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

func testAccessToken(t *testing.T, priv *rsa.PrivateKey, subject, jti string) string {
	t.Helper()
	now := time.Now()
	claims := accessClaims{
		Issuer: testIssuer, Subject: subject, Audience: []string{testAudience},
		ClientID:  testClientID,
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

func testExtractor(t *testing.T) *realip.Extractor {
	t.Helper()
	ex, err := realip.New([]string{"172.28.0.10/32"})
	if err != nil {
		t.Fatalf("realip.New: %v", err)
	}
	return ex
}

func testRequest(authHeader string, extraHeaders map[string]string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/widgets", http.NoBody)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return req
}

// TestWidgetsHandler_GoldenPath confirms a correctly authenticated
// request succeeds and echoes the token's own subject.
func TestWidgetsHandler_GoldenPath(t *testing.T) {
	priv := testRSAKeyPair(t)
	router := newRouter(testValidator(t, priv), testAudience, testExtractor(t), discardLogger())
	token := testAccessToken(t, priv, testSubject, "jti-1")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, testRequest("Bearer "+token, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body widgetsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Subject != testSubject {
		t.Errorf("subject = %q, want %q", body.Subject, testSubject)
	}
	if len(body.Widgets) == 0 {
		t.Error("widgets is empty")
	}
}

// TestWidgetsHandler_MissingToken_Unauthorized and
// TestWidgetsHandler_InvalidSignature_Unauthorized together are #43's
// own first done-when: reached directly (there is no gateway anywhere
// in this test -- the handler is invoked exactly as a direct caller
// would), an invalid token is rejected.
func TestWidgetsHandler_MissingToken_Unauthorized(t *testing.T) {
	priv := testRSAKeyPair(t)
	router := newRouter(testValidator(t, priv), testAudience, testExtractor(t), discardLogger())

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, testRequest("", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestWidgetsHandler_InvalidSignature_Unauthorized is RS-18's own point,
// directly: a token signed by a key this service's own validator never
// trusts is rejected, with no gateway in the picture at all to have
// caught it first.
//
// Negative control: with the `if err != nil { ... }` check removed from
// widgetsHandler after ValidateAccessToken (unconditionally proceeding
// with a zero-value Claims), this test failed -- status was 200 with an
// empty subject, instead of 401. Verified by hand, restored before
// committing.
func TestWidgetsHandler_InvalidSignature_Unauthorized(t *testing.T) {
	priv := testRSAKeyPair(t)
	other := testRSAKeyPair(t) // signs with a key the validator below never trusts
	router := newRouter(testValidator(t, priv), testAudience, testExtractor(t), discardLogger())
	token := testAccessToken(t, other, testSubject, "jti-2")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, testRequest("Bearer "+token, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestWidgetsHandler_ForgedXAuthHeaderChangesNothing is #43's own second
// done-when: a forged X-Auth-* header, sent directly (bypassing the
// gateway that would otherwise have stripped it, RS-17), changes
// nothing -- the response is byte-for-byte identical to the same
// request without that header, because this handler never reads that
// namespace at all (RI-04, T-13).
//
// Negative control: with `claims.Subject` temporarily replaced by
// `r.Header.Get("X-Auth-Subject")` in widgetsHandler's response
// construction, this test failed -- the response's own subject field
// became "mallory", the forged value, instead of "alice". Verified by
// hand, restored before committing.
func TestWidgetsHandler_ForgedXAuthHeaderChangesNothing(t *testing.T) {
	priv := testRSAKeyPair(t)
	router := newRouter(testValidator(t, priv), testAudience, testExtractor(t), discardLogger())
	token := testAccessToken(t, priv, testSubject, "jti-3")

	plain := httptest.NewRecorder()
	router.ServeHTTP(plain, testRequest("Bearer "+token, nil))

	forged := httptest.NewRecorder()
	router.ServeHTTP(forged, testRequest("Bearer "+token, map[string]string{
		"X-Auth-Subject": "mallory",
		"X-Auth-Client":  "someone-elses-client",
		"X-Auth-Scope":   "admin",
	}))

	if plain.Code != http.StatusOK || forged.Code != http.StatusOK {
		t.Fatalf("status = %d / %d (plain/forged), want both %d", plain.Code, forged.Code, http.StatusOK)
	}
	if plain.Body.String() != forged.Body.String() {
		t.Errorf("forged X-Auth-* changed the response:\nplain:  %s\nforged: %s", plain.Body.String(), forged.Body.String())
	}

	var body widgetsResponse
	if err := json.Unmarshal(forged.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode forged response: %v", err)
	}
	if body.Subject != testSubject {
		t.Errorf("subject = %q, want %q (the token's own, never the forged header's)", body.Subject, testSubject)
	}
}

func TestHealthz_NoAuthRequired(t *testing.T) {
	priv := testRSAKeyPair(t)
	router := newRouter(testValidator(t, priv), testAudience, testExtractor(t), discardLogger())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", http.NoBody)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
