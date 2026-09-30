// Command timing-login is REQUIREMENTS §10's timing regression signal for
// RS-14: a statistical comparison of login latency for an existing account
// (wrong password) against a non-existent one. Deliberately not a CI gate —
// timing is inherently noisy, and an automated pass/fail threshold here
// would either flake constantly or be set so loose it catches nothing. Run
// it by hand against a running compose stack, read the two distributions,
// and commit the output under docs/security/ so a future run has a
// baseline to compare against.
//
//	docker compose up -d
//	go run ./scripts/timing-login > docs/security/timing-login-baseline.txt
package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JonasBorgesLM/usher/internal/config"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/store/postgres"
)

const (
	probeIdentifier       = "timing-probe@example.com"
	probePassword         = "timing-probe-real-password"  // #nosec G101 -- fixed probe fixture, not a real credential
	wrongPassword         = "timing-probe-wrong-password" // #nosec G101 -- deliberately wrong, for both groups
	nonExistentIdentifier = "timing-probe-does-not-exist@example.com"
	samplesPerGroup       = 100
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "timing-login:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(config.FromOSEnv)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect to Postgres: %w", err)
	}
	defer pool.Close()
	if migrateErr := postgres.Migrate(ctx, pool); migrateErr != nil {
		return fmt.Errorf("migrate: %w", migrateErr)
	}

	store := postgres.NewUserStore(pool)
	if probeErr := ensureProbeUser(ctx, store); probeErr != nil {
		return probeErr
	}

	hasher, err := identity.NewHasher(8, 5*time.Second, identity.DefaultParams, 1<<30)
	if err != nil {
		return fmt.Errorf("build hasher: %w", err)
	}
	auth, err := identity.NewAuthenticator(store, hasher, identity.DefaultParams)
	if err != nil {
		return fmt.Errorf("build authenticator: %w", err)
	}

	fmt.Printf("timing-login: %d samples per group, interleaved. DefaultParams (m=%d KiB, t=%d, p=%d)\n\n",
		samplesPerGroup, identity.DefaultParams.Memory, identity.DefaultParams.Iterations, identity.DefaultParams.Parallelism)

	existing, nonExistent := sampleInterleaved(ctx, auth)

	printStats("existing identifier, wrong password", existing)
	printStats("non-existent identifier            ", nonExistent)
	fmt.Println()
	fmt.Printf("difference in means: %s\n", absDuration(mean(existing)-mean(nonExistent)))
	fmt.Println("REQUIREMENTS §10: read the two distributions; this is a regression signal, not a threshold to automate.")
	return nil
}

func ensureProbeUser(ctx context.Context, store *postgres.UserStore) error {
	// Canonicalized here, at creation (RS-35), matching Authenticator's own
	// canonicalization at lookup — probeIdentifier is already lowercase
	// ASCII, so this is a no-op today, but the call site stays consistent
	// with cmd/seed's rather than being the one place that assumes so.
	canonical := identity.CanonicalizeIdentifier(probeIdentifier)
	if _, ok, err := store.ByIdentifier(ctx, canonical); err != nil {
		return fmt.Errorf("check for existing probe user: %w", err)
	} else if ok {
		return nil
	}
	hash, err := identity.HashPassword(probePassword, identity.DefaultParams)
	if err != nil {
		return fmt.Errorf("hash probe password: %w", err)
	}
	if _, err := store.CreateUser(ctx, postgres.SeedUser{Identifier: canonical, PasswordHash: hash, Role: "user"}); err != nil {
		return fmt.Errorf("create probe user: %w", err)
	}
	return nil
}

// sampleInterleaved alternates between the two groups rather than running
// one group fully before the other — reduces the risk of a systemic drift
// (thermal throttling, cache state) landing unevenly on one group.
func sampleInterleaved(ctx context.Context, auth *identity.Authenticator) (existing, nonExistent []time.Duration) {
	existing = make([]time.Duration, samplesPerGroup)
	nonExistent = make([]time.Duration, samplesPerGroup)
	for i := 0; i < samplesPerGroup; i++ {
		start := time.Now()
		_, _ = auth.Attempt(ctx, probeIdentifier, wrongPassword) //nolint:errcheck // measuring wall-clock time, not the outcome
		existing[i] = time.Since(start)

		start = time.Now()
		_, _ = auth.Attempt(ctx, nonExistentIdentifier, wrongPassword) //nolint:errcheck // measuring wall-clock time, not the outcome
		nonExistent[i] = time.Since(start)
	}
	return existing, nonExistent
}

func mean(d []time.Duration) time.Duration {
	var sum time.Duration
	for _, v := range d {
		sum += v
	}
	return sum / time.Duration(len(d))
}

func stddev(d []time.Duration, m time.Duration) time.Duration {
	var sumSq float64
	for _, v := range d {
		diff := float64(v - m)
		sumSq += diff * diff
	}
	return time.Duration(math.Sqrt(sumSq / float64(len(d))))
}

func percentile(d []time.Duration, p float64) time.Duration {
	sorted := append([]time.Duration{}, d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(p * float64(len(sorted)-1))
	return sorted[idx]
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func printStats(label string, d []time.Duration) {
	m := mean(d)
	fmt.Printf("%s:  mean=%-12s stddev=%-12s p50=%-12s p95=%-12s p99=%-12s min=%-12s max=%s\n",
		label, m, stddev(d, m), percentile(d, 0.50), percentile(d, 0.95), percentile(d, 0.99),
		percentile(d, 0.0), percentile(d, 1.0))
}
