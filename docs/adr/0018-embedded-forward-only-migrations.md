# ADR-0018: Migrations are embedded SQL, forward-only, applied at startup under an advisory lock

## Status
Accepted — 2026-09-29 (#4)

## Context
REQUIREMENTS §9 named `golang-migrate`; `task-api`, in the same ecosystem,
embeds its SQL and applies it itself. RNF-02 asks that every dependency be
justified, and the schema in phase 0 needs a mechanism before its first file.

## Decision
- Migrations are numbered `.sql` files under `internal/store/postgres/migrations`,
  compiled in with `embed.FS`.
- A `schema_migrations` table records what has been applied. At startup usher
  takes a Postgres advisory lock, applies any pending files in order, each in
  its own transaction, and releases the lock — so two instances starting
  together cannot both migrate.
- Forward-only. A mistake is corrected by the next migration, never by a down
  file. An applied migration's file is never edited; a checksum stored with it
  makes an edit a startup failure (RNF-05).

## The alternative that was rejected
**`golang-migrate`.** Mature, with a CLI, down migrations and many drivers. It
brings a large transitive tree for the one driver used here, and its down
migrations are a feature this project would forbid anyway: on a schema holding
refresh families (ADR-0002), a down migration that drops a column is a
destructive operation someone runs under pressure.

## Consequences
- About a hundred lines of code to own and test, including the lock and the
  checksum check.
- No out-of-band migration tool: the binary migrates its own schema. An operator
  who wants to migrate without serving runs the binary with a migrate-only flag.
- Rolling back a deployment does not roll back the schema; every migration must
  keep the previous binary working (expand, then contract).
