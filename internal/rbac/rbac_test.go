package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testAuthorizer() *Authorizer {
	return New(Permissions{
		"admin": {"task:read", "task:write"},
		"user":  {"task:read"},
	})
}

// TestAllowed_TableOverScopeAndRoleCombinations is the issue's own first
// done-when: scope/role combinations including empty sets, covering RF-05
// as a table rather than a hand-picked few cases.
//
// Negative control: with Allowed's `&&` changed to `||`, six of the
// subtests below failed, flipping from denied to granted -- including
// "scope grants, role lacks" and "role grants, scope lacks", exactly the
// two cases the issue's own second done-when ("scope without role and
// role without scope both denied") names directly. Verified by hand,
// restored before committing.
func TestAllowed_TableOverScopeAndRoleCombinations(t *testing.T) {
	a := testAuthorizer()

	tests := []struct {
		name       string
		permission string
		scope      []string
		role       string
		want       bool
	}{
		{"both grant", "task:write", []string{"task:write"}, "admin", true},
		{"scope grants, role lacks", "task:write", []string{"task:write"}, "user", false},
		{"role grants, scope lacks", "task:write", []string{"openid"}, "admin", false},
		{"neither grants", "task:write", []string{"openid"}, "user", false},
		{"nil scope", "task:read", nil, "admin", false},
		{"empty scope", "task:read", []string{}, "admin", false},
		{"unknown role", "task:read", []string{"task:read"}, "guest", false},
		{"empty role name", "task:read", []string{"task:read"}, "", false},
		{"scope has extra entries, role grants", "task:read", []string{"openid", "task:read"}, "user", true},
		{"both empty", "task:read", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.Allowed(tc.permission, tc.scope, tc.role); got != tc.want {
				t.Errorf("Allowed(%q, %v, %q) = %v, want %v", tc.permission, tc.scope, tc.role, got, tc.want)
			}
		})
	}
}

// TestRequirePermission_DeniesWithoutGrantingContext is the decorator's
// own version of "neither side alone grants": a request whose context
// carries no WithScope/WithRole at all (the shape of a request that
// reached this decorator without an auth layer ever running) is denied,
// not defaulted open.
//
// Negative control: with the `if !a.Allowed(...)` check removed from
// RequirePermission (the wrapped handler always running), this test
// failed -- called became true and the status was 200. Verified by
// hand, restored before committing.
func TestRequirePermission_DeniesWithoutGrantingContext(t *testing.T) {
	a := testAuthorizer()
	called := false
	handler := a.RequirePermission("task:write")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Error("the wrapped handler ran despite no scope/role in context")
	}
}

// TestRequirePermission_GoldenPathCallsHandler confirms the decorator is
// not merely fail-closed but actually passes a correctly granted request
// through to the wrapped handler.
func TestRequirePermission_GoldenPathCallsHandler(t *testing.T) {
	a := testAuthorizer()
	called := false
	handler := a.RequirePermission("task:write")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	ctx := WithRole(WithScope(context.Background(), []string{"task:write"}), "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Error("the wrapped handler never ran despite a granting scope and role")
	}
}

// TestScopeFromAndRoleFrom_RoundTrip is WithScope/WithRole's own
// contract: what goes in through one comes back out through the other,
// and a context that never saw either returns the documented zero
// values rather than panicking.
func TestScopeFromAndRoleFrom_RoundTrip(t *testing.T) {
	ctx := WithRole(WithScope(context.Background(), []string{"a", "b"}), "admin")

	if got := ScopeFrom(ctx); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("ScopeFrom = %v, want [a b]", got)
	}
	if got := RoleFrom(ctx); got != "admin" {
		t.Errorf("RoleFrom = %q, want %q", got, "admin")
	}

	empty := context.Background()
	if got := ScopeFrom(empty); got != nil {
		t.Errorf("ScopeFrom(empty) = %v, want nil", got)
	}
	if got := RoleFrom(empty); got != "" {
		t.Errorf("RoleFrom(empty) = %q, want %q", got, "")
	}
}
