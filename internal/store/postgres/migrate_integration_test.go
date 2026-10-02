//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// newTestPool starts a real postgres:16-alpine container — REQUIREMENTS §10
// forbids a fake here: a fake that implements SET correctly proves nothing
// about the server that has to enforce RS-11's compare-and-set under real
// concurrency. t.Cleanup terminates the container even if the test fails
// partway.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("usher_test"),
		postgres.WithUsername("usher_test"),
		postgres.WithPassword("usher_test"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Logf("terminate postgres container: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestMigrate_AppliesCleanlyToEmptyDatabase(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	for _, table := range []string{"users", "refresh_families", "refresh_tokens", "consent", "schema_migrations"} {
		var exists bool
		err := pool.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("check table %q: %v", table, err)
		}
		if !exists {
			t.Errorf("table %q was not created", table)
		}
	}
}

func TestMigrate_IsIdempotent(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second Migrate (should be a no-op): %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != 1 {
		t.Errorf("schema_migrations has %d rows after two runs, want 1 (no double-apply)", count)
	}
}

// TestMigrate_RefusesAnEditedMigration is ADR-0018's mechanism, verified
// directly: schema_migrations recording a checksum that no longer matches
// the embedded file is a startup failure, never a silent re-apply or skip.
//
// Negative control: with the checksum comparison in Migrate deleted (so a
// recorded row is always treated as "unchanged, skip"), this test fails to
// observe an error — verified by hand while writing this test, not left as
// an assertion nobody watched go red.
func TestMigrate_RefusesAnEditedMigration(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}

	if _, err := pool.Exec(ctx,
		"UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1",
	); err != nil {
		t.Fatalf("simulate an edited migration: %v", err)
	}

	err := Migrate(ctx, pool)
	if err == nil {
		t.Fatal("Migrate succeeded against a tampered checksum; want a refusal (ADR-0018)")
	}
	t.Logf("refused as expected: %v", err)
}

// TestRefreshTokenConsumption_AtomicUnderConcurrency is RS-11 at the SQL
// primitive itself, decoupled from FamilyStore.Rotate's own tests (#36,
// families_integration_test.go): concurrent UPDATE ... WHERE consumed_at
// IS NULL statements against the same row must let exactly one succeed.
// docs/ARCHITECTURE.md §2.2 and the 0001 migration both point at this
// exact query — this test predates Rotate's real implementation and is
// kept as the schema-level pin independent of it; Rotate's own
// concurrency test additionally covers family revocation and the audit
// event, which this one, by design, does not.
//
// Negative control: replacing the WHERE-guarded UPDATE with a SELECT that
// checks consumed_at and only then issues an unconditional UPDATE — the
// shape RS-11 forbids — was run by hand against this test and let more than
// one goroutine "win," confirming the test catches the race it exists for.
func TestRefreshTokenConsumption_AtomicUnderConcurrency(t *testing.T) {
	pool := newTestPool(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var userID string
	if err := pool.QueryRow(ctx,
		"INSERT INTO users (identifier, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
		"race@example.com", "not-a-real-hash-but-twenty-chars", "user",
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	var familyID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO refresh_families (client_id, subject, scope, expires_at)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		"test-client", userID, []string{"openid"}, time.Now().Add(24*time.Hour),
	).Scan(&familyID); err != nil {
		t.Fatalf("insert family: %v", err)
	}

	hash := sha256.Sum256([]byte("the-one-refresh-token-everyone-races-for"))
	if _, err := pool.Exec(ctx,
		`INSERT INTO refresh_tokens (hash, family_id, expires_at) VALUES ($1, $2, $3)`,
		hash[:], familyID, time.Now().Add(24*time.Hour),
	); err != nil {
		t.Fatalf("insert token: %v", err)
	}

	const concurrency = 50
	var wins int64
	done := make(chan struct{})
	for i := 0; i < concurrency; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			tag, err := pool.Exec(ctx,
				"UPDATE refresh_tokens SET consumed_at = now() WHERE hash = $1 AND consumed_at IS NULL",
				hash[:],
			)
			if err != nil {
				t.Errorf("concurrent UPDATE: %v", err)
				return
			}
			if tag.RowsAffected() == 1 {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	for i := 0; i < concurrency; i++ {
		<-done
	}

	if wins != 1 {
		t.Errorf("%d of %d concurrent consumptions reported success, want exactly 1", wins, concurrency)
	}
}
