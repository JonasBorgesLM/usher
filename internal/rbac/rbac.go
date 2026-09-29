// Package rbac evaluates the intersection of a client's granted scopes and a
// user's role (RF-05) — the Decorator pattern REQUIREMENTS §8 names as
// RequirePermission("task:write")(handler). Neither side alone grants
// anything.
//
// Designed and implemented in M5 (REQUIREMENTS §11); this file exists so the
// package is real for check-boundaries.sh and go build before that design is
// written.
package rbac
