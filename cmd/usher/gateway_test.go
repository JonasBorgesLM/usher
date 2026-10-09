package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/bastion"
	"github.com/JonasBorgesLM/usher/internal/rbac"
)

// testGatewayAudience is this file's own fixed audience string -- the
// same role testAudience plays in internal/proxy's own test suite, kept
// separate so a change there cannot silently change what this file
// means by "the resource server's audience".
const testGatewayAudience = "https://resource-server.usher.test"

// newGatewayUpstream starts a test server standing in for
// cmd/resource-server, recording the request it actually received so a
// test can assert what internal/proxy.NewHandler forwarded -- in
// particular, that the "/api" prefix was stripped before the upstream
// ever saw the path (resource-server defines "/widgets", never
// "/api/widgets"; the prefix is this gateway's own convention).
func newGatewayUpstream(t *testing.T) (upstream *httptest.Server, received func() *http.Request) {
	t.Helper()
	var captured *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() *http.Request { return captured }
}

// gatewayDeps builds routerDeps with the gateway mounted against
// upstream, and a client registered with testGatewayAudience so a real
// /token exchange (issueRealAccessToken, userinfo_test.go) mints a
// token this route's own audience check (RS-19) accepts. "widgets:read"
// is added to the client's own registered scopes so the RBAC tests
// below can request it -- RF-05's intersection needs the permission in
// the token's own scope, not just in the role's permissions; a client
// never registered for it could never carry it regardless of role.
func gatewayDeps(t *testing.T, upstream *httptest.Server) routerDeps {
	t.Helper()
	client := testClient()
	client.Audiences = []string{testGatewayAudience}
	client.Scopes = append(client.Scopes, "widgets:read")
	deps := tokenDeps(t, client)
	deps.Denylist = newFakeDenylist()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	deps.GatewayUpstream = u
	deps.GatewayAudience = testGatewayAudience
	return deps
}

// fakeGatewayRoleLookup is this file's own stand-in for the real
// userRoleLookup adapter main.go builds over identity.UserStore -- a
// map keyed by subject, so a test can assign testSubject (what
// issueRealAccessToken's underlying seedCode puts in every token's own
// sub claim) whatever role it needs without a real UserStore.
type fakeGatewayRoleLookup map[string]string

func (f fakeGatewayRoleLookup) RoleOf(_ context.Context, subject string) (string, error) {
	return f[subject], nil
}

// TestGateway_RBAC_RoleHasPermission_Allowed and the test after it are
// RF-05 end to end through the real router: the wiring router.go adds
// to routerDeps (GatewayPermission, GatewayRoles, GatewayAuthorizer),
// not internal/proxy's own already-covered intersection logic.
func TestGateway_RBAC_RoleHasPermission_Allowed(t *testing.T) {
	upstream, _ := newGatewayUpstream(t)
	deps := gatewayDeps(t, upstream)
	deps.GatewayPermission = "widgets:read"
	deps.GatewayRoles = fakeGatewayRoleLookup{testSubject: "admin"}
	deps.GatewayAuthorizer = rbac.New(rbac.Permissions{"admin": {"widgets:read"}})
	mux := newRouter(deps)
	accessToken := issueRealAccessToken(t, deps, mux, []string{"openid", "widgets:read"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getGateway("/api/widgets", "Bearer "+accessToken))

	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/widgets = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// This test's own negative control is its sibling above: the same
// wiring, the same permission, only the role differs -- 200 there, 403
// here. RF-05's own intersection logic (why a role without the
// permission is refused at all) has its negative control in
// internal/proxy/proxy_test.go's TestNewHandler_RBAC_RoleLacksPermission
// _Forbidden; this test is about router.go's own wiring reaching that
// logic, not about re-proving the logic itself.
func TestGateway_RBAC_RoleLacksPermission_Forbidden(t *testing.T) {
	upstream, received := newGatewayUpstream(t)
	deps := gatewayDeps(t, upstream)
	deps.GatewayPermission = "widgets:read"
	deps.GatewayRoles = fakeGatewayRoleLookup{testSubject: "guest"}
	deps.GatewayAuthorizer = rbac.New(rbac.Permissions{"admin": {"widgets:read"}})
	mux := newRouter(deps)
	accessToken := issueRealAccessToken(t, deps, mux, []string{"openid", "widgets:read"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getGateway("/api/widgets", "Bearer "+accessToken))

	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /api/widgets = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if received() != nil {
		t.Error("upstream received a request despite a role with no matching permission")
	}
}

func getGateway(path, authHeader string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://usher.test"+path, http.NoBody)
	req.Host = "usher.test"
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	return req
}

// TestGateway_GoldenPath is #104's own done-when: a token minted via the
// real /authorize -> login -> consent -> /token flow (here, the
// seedCode shortcut issueRealAccessToken already uses for the same
// reason userinfo_test.go does) is accepted at a real, reachable
// /api/** route, which forwards to the upstream with "/api" stripped
// and the client's own bearer token carried unchanged (ADR-0007).
func TestGateway_GoldenPath(t *testing.T) {
	upstream, captured := newGatewayUpstream(t)
	deps := gatewayDeps(t, upstream)
	mux := newRouter(deps)
	accessToken := issueRealAccessToken(t, deps, mux, []string{"openid"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getGateway("/api/widgets", "Bearer "+accessToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/widgets = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	req := captured()
	if req == nil {
		t.Fatal("upstream never received a request")
	}
	if req.URL.Path != "/widgets" {
		t.Errorf("upstream saw path %q, want %q (the /api prefix must be stripped before forwarding)", req.URL.Path, "/widgets")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+accessToken {
		t.Errorf("upstream Authorization = %q, want the client's own bearer token forwarded unchanged (ADR-0007)", got)
	}
}

// TestGateway_RequiresBearerToken is RS-17/RS-18's own starting point:
// no Authorization header at all must never reach the upstream.
func TestGateway_RequiresBearerToken(t *testing.T) {
	upstream, captured := newGatewayUpstream(t)
	deps := gatewayDeps(t, upstream)
	mux := newRouter(deps)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getGateway("/api/widgets", ""))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/widgets with no bearer token = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if captured() != nil {
		t.Error("upstream received a request despite no bearer token -- auth must happen before proxying")
	}
}

// TestGateway_ConsultsDenylist is RF-06/ADR-0014's own gateway-local
// revocation check: a token on the denylist is refused here even though
// its signature and claims are otherwise perfectly valid.
func TestGateway_ConsultsDenylist(t *testing.T) {
	upstream, captured := newGatewayUpstream(t)
	deps := gatewayDeps(t, upstream)
	mux := newRouter(deps)
	accessToken := issueRealAccessToken(t, deps, mux, []string{"openid"})

	pub := deps.Keyset.Published(deps.Now())[0].Private.Public()
	jti := jtiOf(t, accessToken, pub)
	fake := deps.Denylist.(*fakeDenylist)
	if err := fake.Add(t.Context(), jti, time.Hour); err != nil {
		t.Fatalf("Denylist.Add: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getGateway("/api/widgets", "Bearer "+accessToken))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/widgets with a denylisted token = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if captured() != nil {
		t.Error("upstream received a request despite a denylisted token")
	}
}

// TestGateway_NotMountedWhenUpstreamUnset is the "absent by default"
// half: a routerDeps with no GatewayUpstream (every other test file in
// this package builds exactly this) must not expose /api/** at all,
// rather than mounting a handler that can never succeed.
func TestGateway_NotMountedWhenUpstreamUnset(t *testing.T) {
	mux := newRouter(testDeps(t))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, getGateway("/api/widgets", ""))

	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /api/widgets with no gateway configured = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestRouteProperties_GatewayRouteIsClassified is
// TestRouteProperties_EveryRouteIsClassified's own property, re-run
// against a router with the gateway actually mounted -- the plain
// testDeps(t) every other property test in router_test.go uses never
// registers /api/**, so that test alone would never catch a gateway
// route missing from routeGroups.
func TestRouteProperties_GatewayRouteIsClassified(t *testing.T) {
	upstream, _ := newGatewayUpstream(t)
	mux := newRouter(gatewayDeps(t, upstream))
	if uncovered := unclassifiedRoutes(t, mux); len(uncovered) > 0 {
		t.Errorf("routes with no routeGroups entry: %v", uncovered)
	}
}

// recordingHandler keeps every slog record, for asserting on log output.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func recordAttrs(r slog.Record) map[string]string {
	attrs := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	return attrs
}

// TestGatewayBreaker_LogsEachTransitionOnce is #128's other half: with
// per-request rejections no longer logged by internal/proxy, the circuit
// opening and closing must still be visible — once per transition, with
// the states as text rather than bastion's integer State type.
//
// Negative control: with the logger.Log call removed from
// newGatewayBreaker's OnStateChange hook, this test failed — 0 records for
// a trip and a reset. Verified by hand, restored before committing.
func TestGatewayBreaker_LogsEachTransitionOnce(t *testing.T) {
	logs := &recordingHandler{}
	breaker, err := newGatewayBreaker(slog.New(logs))
	if err != nil {
		t.Fatalf("newGatewayBreaker: %v", err)
	}
	ctx := context.Background()

	breaker.Trip(ctx)
	for range 10 { // refused calls while open add nothing
		_, _ = bastion.Execute(ctx, breaker, func(context.Context) (struct{}, error) { return struct{}{}, nil })
	}
	breaker.Reset(ctx)

	if len(logs.records) != 2 {
		t.Fatalf("%d records, want exactly 2 (open, then closed)", len(logs.records))
	}
	opened, closed := logs.records[0], logs.records[1]
	if opened.Level != slog.LevelWarn || recordAttrs(opened)["to"] != "open" {
		t.Errorf("first record = %s %v, want WARN to=open", opened.Level, recordAttrs(opened))
	}
	if closed.Level != slog.LevelInfo || recordAttrs(closed)["to"] != "closed" {
		t.Errorf("second record = %s %v, want INFO to=closed", closed.Level, recordAttrs(closed))
	}
}
