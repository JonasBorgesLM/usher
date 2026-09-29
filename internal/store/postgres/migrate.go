package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationLockKey is the fixed Postgres advisory-lock key ADR-0018's
// single-migrator guarantee is built on. Arbitrary, chosen once, and never
// reused for anything else in this schema.
const migrationLockKey = 0x75736865725F31

// schemaMigrationsDDL creates the bookkeeping table itself, ahead of any
// embedded migration file — it has to exist before Migrate can even ask
// which versions have run.
const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version    INTEGER PRIMARY KEY,
	name       TEXT NOT NULL,
	checksum   TEXT NOT NULL,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

// migration is one parsed, embedded .sql file.
type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

// loadMigrations reads every embedded .sql file and sorts it by the numeric
// prefix in its name ("0001_initial_schema.sql" → version 1).
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("postgres: read embedded migrations: %w", err)
	}

	migs := make([]migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, name, ok := parseMigrationFilename(e.Name())
		if !ok {
			return nil, fmt.Errorf("postgres: migration file %q does not match NNNN_name.sql", e.Name())
		}
		content, err := migrationFiles.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("postgres: read %q: %w", e.Name(), err)
		}
		sum := sha256.Sum256(content)
		migs = append(migs, migration{
			version:  version,
			name:     name,
			sql:      string(content),
			checksum: hex.EncodeToString(sum[:]),
		})
	}

	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	for i := 1; i < len(migs); i++ {
		if migs[i].version == migs[i-1].version {
			return nil, fmt.Errorf("postgres: duplicate migration version %d (%s and %s)",
				migs[i].version, migs[i-1].name, migs[i].name)
		}
	}
	return migs, nil
}

// parseMigrationFilename splits "0001_initial_schema.sql" into (1,
// "initial_schema", true). A name that does not start with a positive
// integer followed by an underscore is rejected rather than silently
// ordered last.
func parseMigrationFilename(filename string) (version int, name string, ok bool) {
	base := strings.TrimSuffix(filename, ".sql")
	parts := strings.SplitN(base, "_", 2)
	if len(parts) != 2 || parts[1] == "" {
		return 0, "", false
	}
	v, err := strconv.Atoi(parts[0])
	if err != nil || v <= 0 {
		return 0, "", false
	}
	return v, parts[1], true
}

// Migrate applies every pending embedded migration to pool's database, under
// a session-level Postgres advisory lock held for the whole batch (ADR-0018)
// — so two instances starting at once do not race each other, while each
// file still commits as its own transaction. An applied file whose current
// checksum no longer matches what schema_migrations recorded is refused
// (RNF-05): the file was edited after being applied, which ADR-0018 forbids
// — a change of mind is a new migration, never an edit to one already run.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	migs, err := loadMigrations()
	if err != nil {
		return err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres: acquire connection for migration lock: %w", err)
	}
	defer conn.Release()

	if _, lockErr := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); lockErr != nil {
		return fmt.Errorf("postgres: acquire migration advisory lock: %w", lockErr)
	}
	defer conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey) //nolint:errcheck // best-effort release; the session ending also releases it

	if _, ddlErr := conn.Exec(ctx, schemaMigrationsDDL); ddlErr != nil {
		return fmt.Errorf("postgres: create schema_migrations: %w", ddlErr)
	}

	applied, err := appliedChecksums(ctx, conn)
	if err != nil {
		return err
	}

	for _, m := range migs {
		if checksum, ok := applied[m.version]; ok {
			if checksum != m.checksum {
				return fmt.Errorf(
					"postgres: migration %04d_%s.sql was edited after being applied (recorded checksum %s, file now %s) — ADR-0018 forbids this; add a new migration instead",
					m.version, m.name, checksum, m.checksum)
			}
			continue
		}
		if err := applyMigration(ctx, conn, m); err != nil {
			return err
		}
	}
	return nil
}

// connExecQuerier is the subset of *pgxpool.Conn this file calls — named so
// appliedChecksums and applyMigration can be exercised without a real pool.
type connExecQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

func appliedChecksums(ctx context.Context, conn connExecQuerier) (map[int]string, error) {
	rows, err := conn.Query(ctx, "SELECT version, checksum FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("postgres: read schema_migrations: %w", err)
	}
	applied := map[int]string{}
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			rows.Close()
			return nil, fmt.Errorf("postgres: scan schema_migrations row: %w", err)
		}
		applied[version] = checksum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: read schema_migrations: %w", err)
	}
	return applied, nil
}

func applyMigration(ctx context.Context, conn connExecQuerier, m migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin transaction for migration %04d_%s: %w", m.version, m.name, err)
	}
	if _, err := tx.Exec(ctx, m.sql); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("postgres: apply migration %04d_%s: %w (rollback also failed: %w)", m.version, m.name, err, rbErr)
		}
		return fmt.Errorf("postgres: apply migration %04d_%s: %w", m.version, m.name, err)
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
		m.version, m.name, m.checksum,
	); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("postgres: record migration %04d_%s: %w (rollback also failed: %w)", m.version, m.name, err, rbErr)
		}
		return fmt.Errorf("postgres: record migration %04d_%s: %w", m.version, m.name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit migration %04d_%s: %w", m.version, m.name, err)
	}
	return nil
}
