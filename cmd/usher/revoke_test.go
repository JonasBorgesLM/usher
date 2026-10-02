package main

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/oauth"
)

// fakeDenylist is cmd/usher's own small stand-in for proxy.Denylist --
// the real one (internal/store/redis) is proven against real Redis in
// its own integration tests (#38); this file tests /revoke's own
// orchestration over the interface.
type fakeDenylist struct {
	mu    sync.Mutex
	added map[string]time.Duration
}

func newFakeDenylist() *fakeDenylist {
	return &fakeDenylist{added: map[string]time.Duration{}}
}

func (d *fakeDenylist) Add(_ context.Context, jti string, ttl time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.added[jti] = ttl
	return nil
}

func (d *fakeDenylist) Contains(_ context.Context, jti string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.added[jti]
	return ok, nil
}

func (d *fakeDenylist) ttlFor(jti string) (time.Duration, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ttl, ok := d.added[jti]
	return ttl, ok
}

func (d *fakeDenylist) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.added)
}

const testOtherRevokeClientID = "other-revoke-client"

// revokeTestClient is testClient()'s own confidential variant with both
// grant types -- #38's tests need a client that can both receive a
// refresh token (authorization_code, with grant_types including
// refresh_token) and present one back to /revoke.
func revokeTestClient(secret string) identity.Client {
	c := confidentialTestClient(secret)
	c.GrantTypes = []string{"authorization_code", "refresh_token"}
	c.Audiences = []string{"https://rs.example"}
	return c
}

// revokeOtherTestClient is a second, distinct confidential client --
// every "this token does not belong to the caller" test needs one that
// is itself validly authenticated, so the rejection is RFC 7009's own
// binding check, never client authentication failing first.
func revokeOtherTestClient(secret string) identity.Client {
	c := revokeTestClient(secret)
	c.ID = testOtherRevokeClientID
	return c
}

func revokeDeps(t *testing.T, clients ...identity.Client) (routerDeps, *fakeDenylist) {
	t.Helper()
	deps := tokenDeps(t, clients...)
	denylist := newFakeDenylist()
	deps.Denylist = denylist
	return deps, denylist
}

func postRevoke(form url.Values, basicUser, basicPass string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://usher.test/revoke", strings.NewReader(form.Encode()))
	req.Host = "usher.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" || basicPass != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	return req
}

// issueAccessTokenForRevoke drives a full authorization_code exchange
// through the real router -- the same round trip
// TestToken_AuthorizationCode_GoldenPath (token_test.go) uses -- so
// #38's tests revoke a token this project's own /token handler actually
// issued, never one assembled by hand.
func issueAccessTokenForRevoke(t *testing.T, deps routerDeps, mux http.Handler, client identity.Client, secret, code string) string {
	t.Helper()
	seedCode(t, deps, code, client.ID, testRedirectURI, []string{"openid", "profile"})
	form := validTokenForm()
	form.Set("code", code)
	form.Set("client_id", client.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(form, client.ID, secret))
	if rec.Code != http.StatusOK {
		t.Fatalf("issue access token: POST /token = %d, body: %s", rec.Code, rec.Body.String())
	}
	body := decodeTokenSuccess(t, rec)
	if body.AccessToken == "" {
		t.Fatal("issue access token: access_token is empty")
	}
	return body.AccessToken
}

// jtiOf decodes an access token's jti without verifying it -- the same
// jwt.WithValidate(false) shortcut TestToken_AuthorizationCode_GoldenPath
// already uses for its own claim assertions; #38's tests only need to
// know which jti the denylist should have received, not to re-verify a
// signature /token's own tests already cover.
func jtiOf(t *testing.T, accessToken string, pub any) string {
	t.Helper()
	parsed, err := jwt.Parse([]byte(accessToken), jwt.WithKey(jwa.RS256(), pub), jwt.WithValidate(false))
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	jti, _ := parsed.JwtID()
	if jti == "" {
		t.Fatal("access token has no jti")
	}
	return jti
}

func decodeRevokeResponse(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /revoke = %d, want %d (RFC 7009 §2.2), body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("POST /revoke body = %q, want empty (RFC 7009 §2.2)", rec.Body.String())
	}
}

func TestRevoke_MissingTokenParam_InvalidRequest(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRevoke(url.Values{}, client.ID, "s3cr3t"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /revoke with no token = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Errorf("body = %s, want invalid_request", rec.Body.String())
	}
}

// TestRevoke_WrongClientSecret_InvalidClient is RS-16 applied to
// /revoke, shared with /token through the same authenticateClient
// function (#38's own refactor) -- not re-tested exhaustively here since
// authenticateClient's own cases are already covered by token_test.go;
// this is the one smoke test confirming /revoke is actually wired to it.
func TestRevoke_WrongClientSecret_InvalidClient(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRevoke(url.Values{"token": {"whatever"}}, client.ID, "wrong-secret"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /revoke with wrong secret = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("WWW-Authenticate header missing on invalid_client")
	}
}

// TestRevoke_AccessToken_GoldenPath is #38's own done-when, driven end to
// end: a genuine access token, revoked by its own issuing client, is
// added to the denylist under its own jti with a TTL equal to its
// remaining lifetime.
func TestRevoke_AccessToken_GoldenPath(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, denylist := revokeDeps(t, client)
	mux := newRouter(deps)
	accessToken := issueAccessTokenForRevoke(t, deps, mux, client, "s3cr3t", "code-access-golden")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRevoke(url.Values{"token": {accessToken}}, client.ID, "s3cr3t"))
	decodeRevokeResponse(t, rec)

	pub := deps.Keyset.Published(deps.Now())[0].Private.Public()
	jti := jtiOf(t, accessToken, pub)

	ttl, ok := denylist.ttlFor(jti)
	if !ok {
		t.Fatal("the access token's jti was never added to the denylist")
	}
	if ttl != deps.AccessTokenTTL {
		t.Errorf("denylist ttl = %s, want %s (the token's own remaining lifetime at a fixed clock)", ttl, deps.AccessTokenTTL)
	}
}

// TestRevoke_AccessToken_AnotherClientGetsSuccessButNotRevoked is RFC
// 7009 §2.1's own binding check: a client presenting a token it was
// never issued still gets 200 (RFC 7009 §2.2's ambiguity), but nothing
// is actually added to the denylist.
//
// Negative control: with the `claims.ClientID != client.ID` check
// removed from revokeAccessToken, this test failed -- the other
// client's token was denylisted by a client it was never issued to.
// Verified by hand, restored before committing.
func TestRevoke_AccessToken_AnotherClientGetsSuccessButNotRevoked(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	other := revokeOtherTestClient("other-secret")
	deps, denylist := revokeDeps(t, client, other)
	mux := newRouter(deps)
	accessToken := issueAccessTokenForRevoke(t, deps, mux, client, "s3cr3t", "code-access-wrong-client")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRevoke(url.Values{"token": {accessToken}}, other.ID, "other-secret"))
	decodeRevokeResponse(t, rec)

	if got := denylist.len(); got != 0 {
		t.Errorf("denylist has %d entries, want 0 -- a different client's token must not be revoked", got)
	}
}

// TestRevoke_AccessToken_TamperedSignatureTreatedAsUnknown is RFC 7009
// §2.2's ambiguity at its own edge: a token that fails signature
// verification is treated exactly like an unknown value -- success, no
// denylist write, and critically not an error (a naive implementation
// might try the refresh-token path and surface some other failure).
func TestRevoke_AccessToken_TamperedSignatureTreatedAsUnknown(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, denylist := revokeDeps(t, client)
	mux := newRouter(deps)
	accessToken := issueAccessTokenForRevoke(t, deps, mux, client, "s3cr3t", "code-access-tampered")
	tampered := accessToken[:len(accessToken)-4] + "AAAA"

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRevoke(url.Values{"token": {tampered}}, client.ID, "s3cr3t"))
	decodeRevokeResponse(t, rec)

	if got := denylist.len(); got != 0 {
		t.Errorf("denylist has %d entries, want 0 for a tampered token", got)
	}
}

// TestRevoke_RefreshToken_GoldenPath is #38's own done-when for the
// refresh side: a refresh token revoked by its own client revokes the
// whole family (RF-06), reusing oauth.FamilyStore.Revoke (#36).
func TestRevoke_RefreshToken_GoldenPath(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	families := deps.Families.(*fakeFamilyStore)
	families.seedFamily(oauth.Family{ClientID: client.ID, Subject: testSubject}, testRefreshToken)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRevoke(url.Values{"token": {testRefreshToken}}, client.ID, "s3cr3t"))
	decodeRevokeResponse(t, rec)

	hash := sha256.Sum256([]byte(testRefreshToken))
	fam, _, err := families.Lookup(context.Background(), hash)
	if err != nil {
		t.Fatalf("Lookup after revoke: %v", err)
	}
	if fam.RevokedAt == nil || fam.RevokedReason != "revoked_by_client" {
		t.Errorf("family RevokedAt=%v RevokedReason=%q, want revoked with reason revoked_by_client", fam.RevokedAt, fam.RevokedReason)
	}
}

// TestRevoke_RefreshToken_AnotherClientGetsSuccessButNotRevoked is the
// refresh side's own version of the access-token binding test: a
// different (but validly authenticated) client presenting someone
// else's refresh token gets 200, but the family is left untouched.
//
// Negative control: with the `fam.ClientID != client.ID` check removed
// from revokeRefreshToken, this test failed -- the other client's
// family was revoked. Verified by hand, restored before committing.
func TestRevoke_RefreshToken_AnotherClientGetsSuccessButNotRevoked(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	other := revokeOtherTestClient("other-secret")
	deps, _ := revokeDeps(t, client, other)
	families := deps.Families.(*fakeFamilyStore)
	families.seedFamily(oauth.Family{ClientID: client.ID, Subject: testSubject}, testRefreshToken)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRevoke(url.Values{"token": {testRefreshToken}}, other.ID, "other-secret"))
	decodeRevokeResponse(t, rec)

	hash := sha256.Sum256([]byte(testRefreshToken))
	fam, _, err := families.Lookup(context.Background(), hash)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if fam.RevokedAt != nil {
		t.Error("a different client's own /revoke call revoked this family")
	}
}

// TestRevoke_UnknownRefreshToken_StillSuccess is RFC 7009 §2.2's
// ambiguity on the refresh side: a value that is neither a valid access
// token nor a known refresh token hash is still 200.
func TestRevoke_UnknownRefreshToken_StillSuccess(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, denylist := revokeDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRevoke(url.Values{"token": {"never-issued-to-anyone"}}, client.ID, "s3cr3t"))
	decodeRevokeResponse(t, rec)

	if got := denylist.len(); got != 0 {
		t.Errorf("denylist has %d entries, want 0", got)
	}
}

// TestRevoke_RefreshToken_AlreadyRevoked_IdempotentNoDuplicateAudit
// confirms revoking an already-revoked family is still success (RFC
// 7009 §2.2, and FamilyStore.Revoke's own idempotency, #36) and does not
// emit a second audit event for a revocation that already happened.
func TestRevoke_RefreshToken_AlreadyRevoked_IdempotentNoDuplicateAudit(t *testing.T) {
	client := revokeTestClient("s3cr3t")
	deps, _ := revokeDeps(t, client)
	sink := audit.NewMemorySink()
	deps.Emitter = sink
	families := deps.Families.(*fakeFamilyStore)
	families.seedFamily(oauth.Family{ClientID: client.ID, Subject: testSubject}, testRefreshToken)
	mux := newRouter(deps)

	first := httptest.NewRecorder()
	mux.ServeHTTP(first, postRevoke(url.Values{"token": {testRefreshToken}}, client.ID, "s3cr3t"))
	decodeRevokeResponse(t, first)

	second := httptest.NewRecorder()
	mux.ServeHTTP(second, postRevoke(url.Values{"token": {testRefreshToken}}, client.ID, "s3cr3t"))
	decodeRevokeResponse(t, second)

	var revocations int
	for _, e := range sink.Events() {
		if e.Type == audit.EventRevocation {
			revocations++
		}
	}
	if revocations != 1 {
		t.Errorf("EventRevocation emitted %d times across two /revoke calls on the same already-revoked family, want exactly 1", revocations)
	}
}
