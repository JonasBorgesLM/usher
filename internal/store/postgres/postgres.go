// Package postgres implements the interfaces REQUIREMENTS §7.1 puts in
// Postgres — identity.UserStore, oauth.FamilyStore, oauth.ConsentStore — over
// the schema in migrations/0001_initial_schema.sql, applied by Migrate
// (ADR-0018). It is imported only from cmd/usher's wiring; no other package
// names its concrete Store types.
//
// Each Store implementation arrives with its own feature issue in M1, M2 and
// M4 (REQUIREMENTS §11) — Migrate and the schema are issue #6's own scope,
// ahead of any of them, because a Store cannot be tested against a table
// that does not exist yet.
package postgres
