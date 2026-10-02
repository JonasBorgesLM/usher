// Package rbac evaluates RF-05: effective permission is the intersection
// of the scopes granted to the client (an OAuth access token's own
// Scope claim) and the permissions of the user's role. Neither side
// alone grants anything — a role holding every permission in existence
// still denies a client whose own token never carried that scope, and a
// token carrying every scope in existence still denies a role with no
// matching permission.
//
// internal/proxy's own [auth] → [rbac] chain order (ADR-0006) is where
// RequirePermission is meant to sit once M6 builds that chain
// (REQUIREMENTS §11). This package depends on neither: WithScope and
// WithRole are the one, deliberately narrow, seam a future auth
// middleware populates and RequirePermission reads — nothing here
// assumes how scope and role were learned.
package rbac

import (
	"context"
	"net/http"
	"slices"
)

type contextKey int

const (
	scopeKey contextKey = iota
	roleKey
)

// WithScope attaches the authenticated request's own granted scope to
// ctx — set by whatever validates the bearer token before
// RequirePermission's handler runs.
func WithScope(ctx context.Context, scope []string) context.Context {
	return context.WithValue(ctx, scopeKey, scope)
}

// ScopeFrom reads back what WithScope attached, or nil if nothing did.
func ScopeFrom(ctx context.Context) []string {
	if scope, ok := ctx.Value(scopeKey).([]string); ok {
		return scope
	}
	return nil
}

// WithRole attaches the authenticated user's own role to ctx.
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, roleKey, role)
}

// RoleFrom reads back what WithRole attached, or "" if nothing did.
func RoleFrom(ctx context.Context) string {
	if role, ok := ctx.Value(roleKey).(string); ok {
		return role
	}
	return ""
}

// Permissions maps a role name to its own fixed set of permissions —
// RF-05's other half, the one that depends on who the user is rather
// than what the client asked for. Static, versioned configuration, the
// same shape identity.Client's own Scopes field already is for RF-01:
// the actual role vocabulary is this type's caller's decision, not this
// package's — cmd/seed's own seedRoles comment already calls "admin"
// and "user" provisional placeholders for exactly that reason.
type Permissions map[string][]string

// Authorizer evaluates RF-05 against one Permissions vocabulary.
type Authorizer struct {
	roles Permissions
}

// New builds an Authorizer. roles may be nil: every role then has no
// permissions at all, a safe default — an unconfigured vocabulary
// denies, it never implicitly grants everything.
func New(roles Permissions) *Authorizer {
	return &Authorizer{roles: roles}
}

// Allowed is RF-05 itself: permission is granted only when it appears in
// BOTH scope and role's own permission set — never from either alone.
func (a *Authorizer) Allowed(permission string, scope []string, role string) bool {
	return slices.Contains(scope, permission) && slices.Contains(a.roles[role], permission)
}

// RequirePermission is the Decorator REQUIREMENTS §8 names:
// RequirePermission("task:write")(handler). A denied request gets 403
// with an empty body — no error detail, the same RS-23/RS-25 discipline
// this project applies to its own protocol errors, extended here since a
// gateway-side denial has nothing a caller is entitled to learn about
// which half of the intersection it failed.
func (a *Authorizer) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.Allowed(permission, ScopeFrom(r.Context()), RoleFrom(r.Context())) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
