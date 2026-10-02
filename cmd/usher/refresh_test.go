package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/oauth"
)

// fakeFamilyStore is a small, controllable stand-in for oauth.FamilyStore
// -- real atomicity and lifetime enforcement are proven elsewhere
// (internal/store/postgres's own integration tests, #35/#36); this
// package's tests are about the /token handler's own orchestration over
// the interface (RS-34's binding checks, #37), not the store.
type fakeFamilyStore struct {
	mu       sync.Mutex
	nextID   int
	families map[string]oauth.Family
	tokens   map[[32]byte]oauth.RefreshToken
}

func newFakeFamilyStore() *fakeFamilyStore {
	return &fakeFamilyStore{families: map[string]oauth.Family{}, tokens: map[[32]byte]oauth.RefreshToken{}}
}

func (f *fakeFamilyStore) CreateFamily(_ context.Context, fam oauth.Family, first oauth.RefreshToken) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := fmt.Sprintf("family-%d", f.nextID)
	fam.ID = id
	f.families[id] = fam
	first.FamilyID = id
	f.tokens[first.Hash] = first
	return id, nil
}

func (f *fakeFamilyStore) Rotate(_ context.Context, hash [32]byte, next oauth.RefreshToken) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tok, ok := f.tokens[hash]
	if !ok || tok.ConsumedAt != nil {
		return false, nil
	}
	now := time.Now()
	tok.ConsumedAt = &now
	f.tokens[hash] = tok
	f.tokens[next.Hash] = next
	return true, nil
}

func (f *fakeFamilyStore) Revoke(_ context.Context, familyID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fam, ok := f.families[familyID]
	if !ok || fam.RevokedAt != nil {
		return nil
	}
	now := time.Now()
	fam.RevokedAt = &now
	fam.RevokedReason = reason
	f.families[familyID] = fam
	return nil
}

func (f *fakeFamilyStore) RevokeAllForSubject(context.Context, string, string) error {
	panic("not used by the /token handler")
}

func (f *fakeFamilyStore) RevokeForSubjectAndClient(context.Context, string, string, string) error {
	panic("not used by the /token handler")
}

func (f *fakeFamilyStore) Lookup(_ context.Context, hash [32]byte) (oauth.Family, oauth.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tok, ok := f.tokens[hash]
	if !ok {
		return oauth.Family{}, oauth.RefreshToken{}, oauth.ErrRefreshTokenNotFound
	}
	fam, ok := f.families[tok.FamilyID]
	if !ok {
		return oauth.Family{}, oauth.RefreshToken{}, oauth.ErrRefreshTokenNotFound
	}
	return fam, tok, nil
}

// seedFamily inserts a family and its one unconsumed token directly,
// bypassing CreateFamily -- the same reasoning #36's own Postgres tests
// already established for seeding fixtures without going through the
// authorization_code grant.
func (f *fakeFamilyStore) seedFamily(fam oauth.Family, rawToken string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := fmt.Sprintf("family-%d", f.nextID)
	fam.ID = id
	f.families[id] = fam
	hash := sha256.Sum256([]byte(rawToken))
	f.tokens[hash] = oauth.RefreshToken{FamilyID: id, Hash: hash, ExpiresAt: time.Now().Add(time.Hour)}
}

func postRefreshToken(form url.Values, basicUser, basicPass string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://usher.test/token", strings.NewReader(form.Encode()))
	req.Host = "usher.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" || basicPass != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	return req
}

const testRefreshToken = "a-real-refresh-token-with-enough-entropy-0123456789"

func validRefreshTokenForm() url.Values {
	return url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {testRefreshToken},
		"client_id":     {testClientID},
	}
}

func TestToken_RefreshToken_GoldenPath(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	store := deps.Families.(*fakeFamilyStore)
	store.seedFamily(oauth.Family{ClientID: testClientID, Subject: testSubject, Scope: []string{"openid", "profile"}, ExpiresAt: time.Now().Add(time.Hour)}, testRefreshToken)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRefreshToken(validRefreshTokenForm(), "", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("refresh_token golden path = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body tokenSuccessBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.AccessToken == "" {
		t.Error("access_token is empty")
	}
	if body.RefreshToken == "" {
		t.Error("refresh_token is empty")
	}
	if body.RefreshToken == testRefreshToken {
		t.Error("refresh_token was not rotated -- the old value was returned again")
	}
	if body.Scope != "openid profile" {
		t.Errorf("scope = %q, want %q", body.Scope, "openid profile")
	}
}

// TestToken_RefreshToken_AnotherClientGetsInvalidGrant is #37's own first
// done-when.
//
// Negative control: with the `fam.ClientID != client.ID` half of the
// binding check removed, this test failed -- a different, but itself
// valid and authenticated, client successfully rotated a token that was
// never issued to it. Verified by hand, restored before committing.
func TestToken_RefreshToken_AnotherClientGetsInvalidGrant(t *testing.T) {
	owner := testClient()
	other := testClient()
	other.ID = "other-client"
	deps := tokenDeps(t, owner, other)
	store := deps.Families.(*fakeFamilyStore)
	store.seedFamily(oauth.Family{ClientID: testClientID, Subject: testSubject, Scope: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour)}, testRefreshToken)
	mux := newRouter(deps)

	form := validRefreshTokenForm()
	form.Set("client_id", "other-client")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRefreshToken(form, "", ""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("another client presenting the token = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"invalid_grant"}`+"\n" {
		t.Errorf("body = %q, want the fixed invalid_grant shape", rec.Body.String())
	}
}

// TestToken_RefreshToken_WiderScopeGetsInvalidScope is #37's own second
// done-when: asking for more than the family's own scope is
// invalid_scope, never a silent upgrade -- and the token itself must
// still be unconsumed afterward, since a rejected request must not have
// spent it.
//
// Negative control: with the `!scopeSubset(requested, fam.Scope)` check
// removed, this test failed -- the wider scope was granted outright (a
// silent upgrade), status 200 instead of invalid_scope. Verified by
// hand, restored before committing.
func TestToken_RefreshToken_WiderScopeGetsInvalidScope(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	store := deps.Families.(*fakeFamilyStore)
	store.seedFamily(oauth.Family{ClientID: testClientID, Subject: testSubject, Scope: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour)}, testRefreshToken)
	mux := newRouter(deps)

	form := validRefreshTokenForm()
	form.Set("scope", "openid profile")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRefreshToken(form, "", ""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wider scope = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if rec.Body.String() != `{"error":"invalid_scope"}`+"\n" {
		t.Errorf("body = %q, want the fixed invalid_scope shape", rec.Body.String())
	}

	// The rejected request must not have consumed the token: a
	// legitimate, correctly-scoped retry still succeeds.
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, postRefreshToken(validRefreshTokenForm(), "", ""))
	if rec2.Code != http.StatusOK {
		t.Fatalf("retry after a rejected wider-scope request = %d, want %d, body: %s", rec2.Code, http.StatusOK, rec2.Body.String())
	}
}

func TestToken_RefreshToken_NarrowerScopeSucceedsWithNarrowedScope(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	store := deps.Families.(*fakeFamilyStore)
	store.seedFamily(oauth.Family{ClientID: testClientID, Subject: testSubject, Scope: []string{"openid", "profile"}, ExpiresAt: time.Now().Add(time.Hour)}, testRefreshToken)
	mux := newRouter(deps)

	form := validRefreshTokenForm()
	form.Set("scope", "openid")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRefreshToken(form, "", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("narrower scope = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeTokenSuccess(t, rec)
	if body.Scope != "openid" {
		t.Errorf("scope = %q, want %q", body.Scope, "openid")
	}
}

func TestToken_RefreshToken_RevokedFamilyGetsInvalidGrant(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	store := deps.Families.(*fakeFamilyStore)
	store.seedFamily(oauth.Family{ClientID: testClientID, Subject: testSubject, Scope: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour)}, testRefreshToken)
	hash := sha256.Sum256([]byte(testRefreshToken))
	familyID := store.tokens[hash].FamilyID
	if err := store.Revoke(context.Background(), familyID, "revoked_by_client"); err != nil {
		t.Fatalf("seed revoke: %v", err)
	}
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRefreshToken(validRefreshTokenForm(), "", ""))

	if rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"invalid_grant"}`+"\n" {
		t.Errorf("revoked family = %d %q, want %d with the fixed invalid_grant shape", rec.Code, rec.Body.String(), http.StatusBadRequest)
	}
}

func TestToken_RefreshToken_UnknownTokenGetsInvalidGrant(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRefreshToken(validRefreshTokenForm(), "", ""))

	if rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"invalid_grant"}`+"\n" {
		t.Errorf("unknown token = %d %q, want %d with the fixed invalid_grant shape", rec.Code, rec.Body.String(), http.StatusBadRequest)
	}
}

// TestToken_RefreshToken_ReuseWithNilEmitterDoesNotPanic is the HTTP-level
// half of internal/oauth's own TestRotateRefreshToken_NilEmitterDoesNotPanic:
// deps.Emitter is left nil, the same as a real deployment that never wires
// RF-09 emission (routerDeps.Emitter's own doc comment: "nil emits
// nothing") -- a reuse attempt through the real /token handler must not
// panic just because nothing is listening for the audit event it tries
// to emit.
func TestToken_RefreshToken_ReuseWithNilEmitterDoesNotPanic(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client) // deps.Emitter left nil
	store := deps.Families.(*fakeFamilyStore)
	store.seedFamily(oauth.Family{ClientID: testClientID, Subject: testSubject, Scope: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour)}, testRefreshToken)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRefreshToken(validRefreshTokenForm(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("first exchange = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, postRefreshToken(validRefreshTokenForm(), "", ""))
	if rec2.Code != http.StatusBadRequest || rec2.Body.String() != `{"error":"invalid_grant"}`+"\n" {
		t.Errorf("replay = %d %q, want %d with the fixed invalid_grant shape", rec2.Code, rec2.Body.String(), http.StatusBadRequest)
	}
}

// TestToken_RefreshToken_ReuseGetsInvalidGrantAndEmitsAudit exercises
// #36's own RotateRefreshToken through the real HTTP handler: a second
// presentation of an already-rotated token is reuse.
func TestToken_RefreshToken_ReuseGetsInvalidGrantAndEmitsAudit(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	sink := audit.NewMemorySink()
	deps.Emitter = sink
	store := deps.Families.(*fakeFamilyStore)
	store.seedFamily(oauth.Family{ClientID: testClientID, Subject: testSubject, Scope: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour)}, testRefreshToken)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postRefreshToken(validRefreshTokenForm(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("first exchange = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, postRefreshToken(validRefreshTokenForm(), "", ""))
	if rec2.Code != http.StatusBadRequest || rec2.Body.String() != `{"error":"invalid_grant"}`+"\n" {
		t.Errorf("replay = %d %q, want %d with the fixed invalid_grant shape", rec2.Code, rec2.Body.String(), http.StatusBadRequest)
	}

	var found bool
	for _, e := range sink.Events() {
		if e.Type == audit.EventRefreshReuse {
			found = true
		}
	}
	if !found {
		t.Error("no EventRefreshReuse event was emitted for the replay")
	}
}

// TestToken_AuthorizationCode_IssuesRefreshTokenWhenGrantTypeAllows is
// RF-02 Flow 2 steps 6-7: a client whose grant_types include
// refresh_token gets one from the authorization_code exchange too.
func TestToken_AuthorizationCode_IssuesRefreshTokenWhenGrantTypeAllows(t *testing.T) {
	client := testClient()
	client.GrantTypes = []string{"authorization_code", "refresh_token"}
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("authorization_code exchange = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeTokenSuccess(t, rec)
	if body.RefreshToken == "" {
		t.Error("refresh_token is empty, want one issued (grant_types includes refresh_token)")
	}

	// And the newly issued refresh_token must itself be usable.
	rec2 := httptest.NewRecorder()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {body.RefreshToken}, "client_id": {testClientID}}
	mux.ServeHTTP(rec2, postRefreshToken(form, "", ""))
	if rec2.Code != http.StatusOK {
		t.Errorf("using the newly issued refresh_token = %d, want %d, body: %s", rec2.Code, http.StatusOK, rec2.Body.String())
	}
}

// TestToken_AuthorizationCode_NoRefreshTokenWhenGrantTypeExcludes is the
// other half: a client not configured for refresh_token never gets one,
// even though the handler now knows how to issue one.
func TestToken_AuthorizationCode_NoRefreshTokenWhenGrantTypeExcludes(t *testing.T) {
	client := testClient() // GrantTypes: ["authorization_code"] only
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("authorization_code exchange = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "refresh_token") {
		t.Errorf("response unexpectedly carries a refresh_token: %s", rec.Body.String())
	}
}
