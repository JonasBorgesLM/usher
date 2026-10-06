package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/usher/internal/oauth"
)

func postIntrospect(form url.Values, basicUser, basicPass string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://usher.test/introspect", strings.NewReader(form.Encode()))
	req.Host = "usher.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" || basicPass != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	return req
}

func decodeIntrospectBody(t *testing.T, rec *httptest.ResponseRecorder) introspectBody {
	t.Helper()
	var body introspectBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode introspect body: %v, raw: %s", err, rec.Body.String())
	}
	return body
}

// TestIntrospect_MissingTokenParam_InvalidRequest mirrors
// TestRevoke_MissingTokenParam_InvalidRequest: RFC 7662's own required
// parameter, reported before client authentication is even checked --
// the same order /revoke already uses.
func TestIntrospect_MissingTokenParam_InvalidRequest(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{}, client.ID, "s3cr3t"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing token = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"invalid_request"}`+"\n" {
		t.Errorf("body = %q, want the fixed invalid_request shape", rec.Body.String())
	}
}

// TestIntrospect_UnauthenticatedCaller_Refused is the issue's own first
// done-when: no client credentials at all is refused outright, never
// {"active": false} -- RFC 7662 §2.1 requires the caller to authenticate,
// and failing that is reported distinctly, the same way /revoke already
// treats a missing-or-wrong secret as invalid_client rather than folding
// it into whatever ambiguity covers the token's own state.
//
// Negative control: with the authentication-failure branch in
// introspect.go's ServeHTTP disabled (errCode's check short-circuited
// to false), this test failed -- status was 200, body {"active":false},
// instead of the 401 refusal RFC 7662 §2.1 requires: the request
// reached introspection as the zero identity.Client instead of being
// refused outright. Verified by hand, restored before committing.
func TestIntrospect_UnauthenticatedCaller_Refused(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {"anything"}}, "", ""))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated caller = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"invalid_client"}`+"\n" {
		t.Errorf("body = %q, want the fixed invalid_client shape", rec.Body.String())
	}
}

// TestIntrospect_WrongClientSecret_InvalidClient mirrors
// TestRevoke_WrongClientSecret_InvalidClient: a real client_id with the
// wrong secret is the same invalid_client refusal, not folded into
// {"active": false} either.
func TestIntrospect_WrongClientSecret_InvalidClient(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {"anything"}}, client.ID, "wrong-secret"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"invalid_client"}`+"\n" {
		t.Errorf("body = %q, want the fixed invalid_client shape", rec.Body.String())
	}
}

// TestIntrospect_AccessToken_GoldenPath introspects a token /token itself
// actually issued, through the real Keyset -- not one assembled by hand
// -- and asserts the full RFC 7662 §2.2 claim set this project can
// answer truthfully.
func TestIntrospect_AccessToken_GoldenPath(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	mux := newRouter(deps)
	accessToken := issueAccessTokenForRevoke(t, deps, mux, client, "s3cr3t", "code-1")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {accessToken}}, client.ID, "s3cr3t"))

	if rec.Code != http.StatusOK {
		t.Fatalf("introspect golden path = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeIntrospectBody(t, rec)
	if !body.Active {
		t.Fatal("active = false, want true for a genuinely live access token")
	}
	if body.ClientID != client.ID {
		t.Errorf("client_id = %q, want %q", body.ClientID, client.ID)
	}
	if body.Scope != "openid profile" {
		t.Errorf("scope = %q, want %q", body.Scope, "openid profile")
	}
	if body.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want %q", body.TokenType, "Bearer")
	}
	if body.Subject != testSubject {
		t.Errorf("sub = %q, want %q", body.Subject, testSubject)
	}
	if body.Issuer != deps.Issuer {
		t.Errorf("iss = %q, want %q", body.Issuer, deps.Issuer)
	}
	// issueAccessTokenForRevoke's own scope ("openid profile") also adds
	// the userinfo audience (#45) alongside the resource server's own --
	// both are genuinely this token's aud, not a surprise this test
	// should narrow away.
	wantAud := []string{"https://rs.example", "https://usher.test/userinfo"}
	if !slices.Equal(body.Audience, wantAud) {
		t.Errorf("aud = %v, want %v", body.Audience, wantAud)
	}
	if body.ExpiresAt == 0 {
		t.Error("exp is missing")
	}
	if body.IssuedAt == 0 {
		t.Error("iat is missing")
	}
	if body.JTI == "" {
		t.Error("jti is missing")
	}
}

// TestIntrospect_AccessToken_ForeignClientGetsInactive is the issue's
// own "foreign tokens" done-when: a real, live access token introspected
// by a client other than the one it was issued to gets {"active":
// false} -- not an error, and not the token's own real state.
//
// Negative control: with the `claims.ClientID != client.ID` check
// removed from introspectAccessToken, this test failed -- the other
// client's own introspection reported active:true for a token that was
// never issued to it. Verified by hand, restored before committing.
func TestIntrospect_AccessToken_ForeignClientGetsInactive(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	other := revokeOtherTestClient("other-secret")
	deps, _ := revokeDeps(t, client, other)
	mux := newRouter(deps)
	accessToken := issueAccessTokenForRevoke(t, deps, mux, client, "s3cr3t", "code-1")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {accessToken}}, other.ID, "other-secret"))

	if rec.Code != http.StatusOK {
		t.Fatalf("foreign access token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != `{"active":false}`+"\n" {
		t.Errorf("body = %q, want the fixed inactive shape", rec.Body.String())
	}
}

// TestIntrospect_TamperedAccessToken_Inactive stands in for "never a
// genuine token at all": a signature that does not verify is treated
// exactly like a refresh-token lookup miss, falling all the way through
// to the same inactive body.
func TestIntrospect_TamperedAccessToken_Inactive(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	mux := newRouter(deps)
	accessToken := issueAccessTokenForRevoke(t, deps, mux, client, "s3cr3t", "code-1")
	tampered := accessToken[:len(accessToken)-4] + "AAAA"

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {tampered}}, client.ID, "s3cr3t"))

	if rec.Code != http.StatusOK {
		t.Fatalf("tampered token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != `{"active":false}`+"\n" {
		t.Errorf("body = %q, want the fixed inactive shape", rec.Body.String())
	}
}

// TestIntrospect_RefreshToken_GoldenPath is the refresh-token half of
// the golden path: a live, unconsumed, unrevoked family introspected by
// its own client.
func TestIntrospect_RefreshToken_GoldenPath(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	families := deps.Families.(*fakeFamilyStore)
	families.seedFamily(oauth.Family{ClientID: client.ID, Subject: testSubject, Scope: []string{"openid"}}, testRefreshToken)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {testRefreshToken}}, client.ID, "s3cr3t"))

	if rec.Code != http.StatusOK {
		t.Fatalf("introspect refresh token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeIntrospectBody(t, rec)
	if !body.Active {
		t.Fatal("active = false, want true for a genuinely live refresh token")
	}
	if body.ClientID != client.ID {
		t.Errorf("client_id = %q, want %q", body.ClientID, client.ID)
	}
	if body.Subject != testSubject {
		t.Errorf("sub = %q, want %q", body.Subject, testSubject)
	}
	if body.Scope != "openid" {
		t.Errorf("scope = %q, want %q", body.Scope, "openid")
	}
	if body.ExpiresAt == 0 {
		t.Error("exp is missing")
	}
}

// TestIntrospect_RefreshToken_RevokedGetsInactive is the issue's own
// "revoked ... tokens" done-when, the refresh-token half.
//
// Negative control: with the `fam.RevokedAt != nil` half of the check
// removed from introspectRefreshToken, this test failed -- a revoked
// family still reported active:true. Verified by hand, restored before
// committing.
func TestIntrospect_RefreshToken_RevokedGetsInactive(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	families := deps.Families.(*fakeFamilyStore)
	families.seedFamily(oauth.Family{ClientID: client.ID, Subject: testSubject}, testRefreshToken)
	hash := sha256.Sum256([]byte(testRefreshToken))
	fam, _, err := families.Lookup(context.Background(), hash)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if err := families.Revoke(context.Background(), fam.ID, "revoked_by_client"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {testRefreshToken}}, client.ID, "s3cr3t"))

	if rec.Code != http.StatusOK {
		t.Fatalf("revoked refresh token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != `{"active":false}`+"\n" {
		t.Errorf("body = %q, want the fixed inactive shape", rec.Body.String())
	}
}

// TestIntrospect_RefreshToken_ConsumedGetsInactive: this exact raw value
// was already rotated away by a prior refresh exchange. The family
// itself is still live -- its successor is -- but this specific token
// value is spent and must not report active.
//
// Negative control: with the `tok.ConsumedAt != nil` half of the check
// removed from introspectRefreshToken, this test failed -- an already-
// consumed token value still reported active:true. Verified by hand,
// restored before committing.
func TestIntrospect_RefreshToken_ConsumedGetsInactive(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	families := deps.Families.(*fakeFamilyStore)
	families.seedFamily(oauth.Family{ClientID: client.ID, Subject: testSubject}, testRefreshToken)
	hash := sha256.Sum256([]byte(testRefreshToken))
	// Rotate consumes testRefreshToken's own hash and inserts a
	// successor -- the same transition a real refresh_token grant
	// exchange causes.
	if _, err := families.Rotate(context.Background(), hash, oauth.RefreshToken{Hash: sha256.Sum256([]byte("successor"))}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {testRefreshToken}}, client.ID, "s3cr3t"))

	if rec.Code != http.StatusOK {
		t.Fatalf("consumed refresh token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != `{"active":false}`+"\n" {
		t.Errorf("body = %q, want the fixed inactive shape", rec.Body.String())
	}
}

// TestIntrospect_RefreshToken_ForeignClientGetsInactive is the refresh-
// token half of the "foreign tokens" done-when.
func TestIntrospect_RefreshToken_ForeignClientGetsInactive(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	other := revokeOtherTestClient("other-secret")
	deps, _ := revokeDeps(t, client, other)
	families := deps.Families.(*fakeFamilyStore)
	families.seedFamily(oauth.Family{ClientID: client.ID, Subject: testSubject}, testRefreshToken)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {testRefreshToken}}, other.ID, "other-secret"))

	if rec.Code != http.StatusOK {
		t.Fatalf("foreign refresh token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != `{"active":false}`+"\n" {
		t.Errorf("body = %q, want the fixed inactive shape", rec.Body.String())
	}
}

// TestIntrospect_UnknownToken_Inactive stands in for "expired": Lookup's
// own semantics (internal/oauth's doc comment on FamilyStore.Lookup)
// already fold "never existed" and "past its own lifetime" into the
// identical ErrRefreshTokenNotFound, so a value that was simply never
// issued exercises the same path a genuinely expired one would.
func TestIntrospect_UnknownToken_Inactive(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {"never-issued-to-anyone"}}, client.ID, "s3cr3t"))

	if rec.Code != http.StatusOK {
		t.Fatalf("unknown token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != `{"active":false}`+"\n" {
		t.Errorf("body = %q, want the fixed inactive shape", rec.Body.String())
	}
}

// TestIntrospect_InactiveCausesYieldIdenticalBody is the issue's own
// second done-when, stated directly: revoked, foreign and never-issued
// ("expired") tokens all produce byte-for-byte the same body, so a
// caller cannot distinguish any of these causes by response shape
// (RS-25's ambiguity principle).
func TestIntrospect_InactiveCausesYieldIdenticalBody(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	other := revokeOtherTestClient("other-secret")
	deps, _ := revokeDeps(t, client, other)
	mux := newRouter(deps)
	families := deps.Families.(*fakeFamilyStore)

	families.seedFamily(oauth.Family{ClientID: client.ID, Subject: testSubject}, "revoked-token")
	hash := sha256.Sum256([]byte("revoked-token"))
	fam, _, err := families.Lookup(context.Background(), hash)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if err := families.Revoke(context.Background(), fam.ID, "revoked_by_client"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	families.seedFamily(oauth.Family{ClientID: other.ID, Subject: testSubject}, "foreign-token")

	// Issued to other, introspected below by client -- genuinely foreign
	// to the caller, unlike the other three cases above which are
	// client's own tokens in one state or another of "not usable."
	foreignAccessToken := issueAccessTokenForRevoke(t, deps, mux, other, "other-secret", "code-1")

	cases := map[string]string{
		"revoked refresh token":  "revoked-token",
		"foreign refresh token":  "foreign-token",
		"never issued (expired)": "never-issued-to-anyone",
		"foreign access token":   foreignAccessToken,
	}

	var bodies []string
	for name, token := range cases {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {token}}, client.ID, "s3cr3t"))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want %d", name, rec.Code, http.StatusOK)
		}
		bodies = append(bodies, rec.Body.String())
	}

	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("inactive bodies differ: %q vs %q", bodies[0], bodies[i])
		}
	}
	if bodies[0] != `{"active":false}`+"\n" {
		t.Errorf("inactive body = %q, want the fixed, detail-free shape", bodies[0])
	}
}

// TestIntrospect_NoStore mirrors the same assertion token_test.go and
// revoke_test.go each already make for their own routes: /introspect is
// in the same tokenGroup (RS-26).
func TestIntrospect_NoStore(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postIntrospect(url.Values{"token": {"anything"}}, client.ID, "s3cr3t"))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q (RS-26)", got, "no-store")
	}
}
