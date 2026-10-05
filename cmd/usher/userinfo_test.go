package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func getUserinfo(authHeader string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test/userinfo", http.NoBody)
	req.Host = "usher.test"
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	return req
}

// issueRealAccessToken drives a full, real authorization_code exchange —
// the same seedCode + POST /token this file's sibling token_test.go
// already uses — rather than hand-signing a token, so the token /userinfo
// sees here carries exactly whatever issueAccessToken (token.go) actually
// puts in it, including the RS-08 userinfo-audience addition #45 adds.
func issueRealAccessToken(t *testing.T, deps routerDeps, mux *chi.Mux, scope []string) string {
	t.Helper()
	seedCode(t, deps, testTokenCode, testClientID, testRedirectURI, scope)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, postToken(validTokenForm(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	return decodeTokenSuccess(t, rec).AccessToken
}

// TestUserinfo_GoldenPath is RS-08's /userinfo half, end to end: an
// access token genuinely issued for an openid-scoped authorization_code
// exchange is accepted at /userinfo and returns the one claim usher's
// own User model has anything to say about, sub.
func TestUserinfo_GoldenPath(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	accessToken := issueRealAccessToken(t, deps, mux, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getUserinfo("Bearer "+accessToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /userinfo = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body userinfoBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode userinfo body: %v, raw: %s", err, rec.Body.String())
	}
	if body.Subject != testSubject {
		t.Errorf("sub = %q, want %q", body.Subject, testSubject)
	}
}

// TestUserinfo_NoStore is #45's own second done-when: Cache-Control:
// no-store on /userinfo's response, success and failure alike (RS-26) —
// the same dual-path shape TestToken_NoStoreOnSuccessAndError already
// uses for /token.
//
// Negative control: with userinfoGroup.noStore changed to false, this
// test failed on both paths -- Cache-Control was absent entirely.
// Verified by hand, restored before committing.
func TestUserinfo_NoStore(t *testing.T) {
	client := testClient()
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	accessToken := issueRealAccessToken(t, deps, mux, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getUserinfo("Bearer "+accessToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("golden path = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("success Cache-Control = %q, want %q", got, "no-store")
	}

	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, getUserinfo(""))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer token = %d, want %d", rec2.Code, http.StatusUnauthorized)
	}
	if got := rec2.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("error Cache-Control = %q, want %q", got, "no-store")
	}
}

// TestUserinfo_MissingBearerToken_Unauthorized is RS-08's own baseline:
// no Authorization header at all gets 401, the same bare, bodyless
// response every other failure cause here gets (RS-23/RS-25).
func TestUserinfo_MissingBearerToken_Unauthorized(t *testing.T) {
	deps := tokenDeps(t, testClient())
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getUserinfo(""))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty (RS-23/RS-25)", rec.Body.String())
	}
}

// TestUserinfo_TokenWithoutUserinfoAudience_Unauthorized is #45's own
// first done-when: a token genuinely issued for a request whose scope
// never included openid never carries usher's own userinfo audience
// (issueAccessToken, token.go) and is refused here -- it is otherwise a
// perfectly valid, correctly signed access token, which is exactly the
// case worth proving: the refusal is RS-08's audience check, not a
// signature or issuer mismatch that would refuse any token at all.
//
// Negative control: with h.audience replaced by "" in userinfoHandler
// .ServeHTTP's own ValidateAccessToken call (disabling the audience
// requirement entirely -- jwx's own documented behavior for an empty
// wantAudience), this test failed -- status was 200 and the response
// carried sub, for a token RS-08 says must be refused here. Verified by
// hand, restored before committing.
func TestUserinfo_TokenWithoutUserinfoAudience_Unauthorized(t *testing.T) {
	client := testClient()
	// A real resource-server audience, so the token this issues has a
	// genuine, non-empty aud -- one that simply never gained the
	// userinfo entry, not an aud-less token refused for an unrelated
	// reason (claims shape, not RS-08's own check).
	client.Audiences = []string{"https://rs.example"}
	deps := tokenDeps(t, client)
	mux := newRouter(deps)
	accessToken := issueRealAccessToken(t, deps, mux, []string{"profile"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getUserinfo("Bearer "+accessToken))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (access token without the userinfo audience)", rec.Code, http.StatusUnauthorized)
	}
}

// TestUserinfo_WrongMethod_NotAllowed documents that only GET is
// registered (REQUIREMENTS §7.2's own "GET /userinfo"), the same
// chi-provided 405 every other single-method route here already gets for
// free -- not a new check this file adds.
func TestUserinfo_WrongMethod_NotAllowed(t *testing.T) {
	deps := tokenDeps(t, testClient())
	mux := newRouter(deps)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://usher.test/userinfo", http.NoBody)
	req.Host = "usher.test"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /userinfo = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
