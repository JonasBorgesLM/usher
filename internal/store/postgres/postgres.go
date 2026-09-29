// Package postgres implements the interfaces REQUIREMENTS §7.1 puts in
// Postgres — identity.UserStore, oauth.FamilyStore, oauth.ConsentStore — plus
// the embedded, forward-only migration runner (ADR-0018). It is imported
// only from cmd/usher's wiring; no other package names its concrete types.
//
// Migrations arrive with issue #6; each Store implementation arrives with
// its own feature issue in M1, M2 and M4 (REQUIREMENTS §11). This file
// exists so the package is real for check-boundaries.sh and go build before
// that code is written.
package postgres
