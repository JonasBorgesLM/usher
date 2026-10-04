// Command usher runs the OAuth 2.1 / OpenID Connect authorization server and
// the reverse-proxy gateway in one process, with rigid package boundaries
// between them (ADR-0001). See REQUIREMENTS.md §11 for the phase plan this
// binary is wired up incrementally against.
//
// main itself does only two things: load configuration (config.Load is the
// one place allowed to read the environment) and construct every
// dependency newRouter and serve already know how to use — assembly, not
// design. Every constructor called below already has its own tests where
// it is defined; this file's own job is to call them in the right order
// and fail closed (RNF-05) if any of them refuses.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/config"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/keys"
	"github.com/JonasBorgesLM/usher/internal/store/postgres"
	"github.com/JonasBorgesLM/usher/internal/store/redis"
)

// Rate-limit tiers (RF-07: "credential routes are limited far more
// aggressively than proxied reads"). REQUIREMENTS names the property, not
// a number — these are this deployment's own calibration, not a
// requirement restated. The account axis (RS-22) shares the login tier's
// own numbers: both exist to slow the same attack, from the two angles
// RS-22's own reasoning gives for needing both.
const (
	loginBurst            = 5
	loginPerSecond        = 1
	authorizeBurst        = 20
	authorizePerSecond    = 5
	accountBurst          = 5
	accountPerSecond      = 1
	crierBufferSize       = 1024
	crierRequestTimeout   = 5 * time.Second
	shutdownDrainDeadline = 10 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "usher:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(config.FromOSEnv)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	logger := newProductionLogger(os.Stdout)
	ctx := context.Background()

	// pool, redisClient and rateLimitStore are deliberately never
	// deferred here: serve's own closers parameter below is the one
	// place they are closed, with errors logged rather than discarded,
	// during a graceful shutdown. A construction failure on any line
	// between here and serve (which os.Exit(1) follows immediately,
	// per main's own call to run) leaks a connection only until process
	// exit reclaims it -- a real cost only if this function is ever
	// called somewhere that outlives a single failed attempt, which it
	// is not.
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect to Postgres: %w", err)
	}
	if migrateErr := postgres.Migrate(ctx, pool); migrateErr != nil {
		return fmt.Errorf("migrate: %w", migrateErr)
	}

	redisClient := goredis.NewClient(&goredis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword})

	// RNF-07: refuses to start if the server cannot be proven to run
	// noeviction. Shared by every rate limiter below (WithStore's own
	// doc comment: "normally shared by several limiters").
	rateLimitStore, err := redis.NewRateLimitStore(redisClient)
	if err != nil {
		return fmt.Errorf("build rate-limit store: %w", err)
	}

	keyFunc, err := cfg.BuildKeyFunc()
	if err != nil {
		return fmt.Errorf("build rate-limit key function: %w", err)
	}

	loginLimiter := ratelimit.New(loginBurst, loginPerSecond, ratelimit.WithStore(rateLimitStore), ratelimit.WithKeyFunc(keyFunc))
	authorizeLimiter := ratelimit.New(authorizeBurst, authorizePerSecond, ratelimit.WithStore(rateLimitStore), ratelimit.WithKeyFunc(keyFunc))
	// accountLimiter's own key is the canonicalized identifier
	// (internal/identity.Authenticator calls Allow(ctx, canonical)
	// directly, never through Middleware), so WithKeyFunc would never be
	// consulted — RS-22's account axis, not the IP axis above.
	accountLimiter := ratelimit.New(accountBurst, accountPerSecond, ratelimit.WithStore(rateLimitStore))

	csrfProtector, err := csrf.New(cfg.CSRFSecret)
	if err != nil {
		return fmt.Errorf("build CSRF protector: %w", err)
	}

	clients, err := identity.LoadClients(cfg.ClientsPath, []string{"https", "http"})
	if err != nil {
		return fmt.Errorf("load client registry: %w", err)
	}

	userStore := postgres.NewUserStore(pool)
	hasher, err := identity.NewHasher(cfg.HashConcurrency, cfg.HashWait, identity.DefaultParams, cfg.HashMemoryCeilingKiB)
	if err != nil {
		return fmt.Errorf("build password hasher: %w", err)
	}
	authenticator, err := identity.NewAuthenticator(userStore, hasher, identity.DefaultParams, identity.WithAccountLimiter(accountLimiter))
	if err != nil {
		return fmt.Errorf("build authenticator: %w", err)
	}

	denylist := redis.NewDenylist(redisClient)
	keyset, err := keys.Load(cfg.KeysDir, lifetimeClockSkew, cfg.AccessTokenTTL, cfg.ConsumerJWKSCacheTTL, nil)
	if err != nil {
		return fmt.Errorf("load signing keyset: %w", err)
	}

	var emitter audit.Emitter
	if cfg.CrierURL != "" {
		crierEmitter := audit.NewCrierEmitter(&http.Client{Timeout: crierRequestTimeout}, cfg.CrierURL, cfg.CrierServiceName, cfg.CrierToken, crierBufferSize, logger)
		defer crierEmitter.Close()
		emitter = crierEmitter
	}

	deps := routerDeps{
		Authenticator:        authenticator,
		Sessions:             redis.NewSessionStore(redisClient, cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL),
		Challenges:           redis.NewChallengeStore(redisClient),
		CSRFProtector:        csrfProtector,
		LoginLimiter:         loginLimiter,
		Emitter:              emitter,
		ReadinessChecks:      readinessChecks(pool, redisClient, keyset),
		Clients:              clients,
		AuthorizeLimiter:     authorizeLimiter,
		Issuer:               cfg.Issuer,
		ChallengeTTL:         cfg.ChallengeTTL,
		Consents:             postgres.NewConsentStore(pool),
		Codes:                redis.NewCodeStore(redisClient),
		Keyset:               keyset,
		AuthCodeTTL:          cfg.AuthCodeTTL,
		AccessTokenTTL:       cfg.AccessTokenTTL,
		Families:             postgres.NewFamilyStore(pool),
		RefreshIdleTTL:       cfg.RefreshIdleTTL,
		RefreshAbsoluteTTL:   cfg.RefreshAbsoluteTTL,
		Denylist:             denylist,
		ConsumerJWKSCacheTTL: cfg.ConsumerJWKSCacheTTL,
		SessionIdleTTL:       cfg.SessionIdleTTL,
		SessionAbsoluteTTL:   cfg.SessionAbsoluteTTL,
		Logger:               logger,
	}

	srv := newServer(newRouter(deps))
	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return serve(shutdownCtx, srv, ln, shutdownDrainDeadline, logger,
		func() error { return rateLimitStore.Close() },
		func() error { return redisClient.Close() },
		func() error { pool.Close(); return nil }, // pgxpool.Pool.Close has no return value
	)
}

// lifetimeClockSkew is keys.Load's own clockSkew parameter: the margin
// RS-09's retirement formula leaves for drift between instances'
// clocks, folded into how long a retiring key must stay published after
// its successor starts signing. It is not shared with anything else in
// this file -- router.go's own revokeValidator (#38) and the gateway's
// validator (#40) are both built with tokenvalidator's default (zero)
// clock skew today, since neither configures WithClockSkew. REQUIREMENTS
// names the property keys.Load needs a number for, not the number
// itself, so this is this deployment's own choice.
const lifetimeClockSkew = 30 * time.Second

// readinessChecks is RNF-10's own dependency list: Postgres, Redis and
// the signing keyset currently having an active key to sign with. The
// rate-limit store's own eviction policy (RNF-07) is checked once, at
// construction above — if it were unsafe, run would already have
// returned before reaching this point, so there is nothing left for
// /readyz to poll about it.
func readinessChecks(pool *pgxpool.Pool, redisClient *goredis.Client, keyset *keys.Keyset) []ReadinessCheck {
	return []ReadinessCheck{
		{Name: "postgres", Check: func(ctx context.Context) error { return pool.Ping(ctx) }},
		{Name: "redis", Check: func(ctx context.Context) error { return redisClient.Ping(ctx).Err() }},
		{Name: "signing_key", Check: func(context.Context) error {
			_, err := keyset.Signing(time.Now())
			return err
		}},
	}
}
