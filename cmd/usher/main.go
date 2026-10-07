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
	"net/url"
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
	"github.com/JonasBorgesLM/usher/internal/rbac"
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

	// gatewayWidgetsReadPermission is RF-05's own permission string for
	// the one route this deployment proxies, cmd/resource-server's
	// GET /widgets. REQUIREMENTS names the property (effective
	// permission = scope ∩ role), not a permission vocabulary — this
	// deployment's own choice, like the rate-limit tiers above.
	gatewayWidgetsReadPermission = "widgets:read"
)

// gatewayRolePermissions is this deployment's own role vocabulary for
// the one gateway route it proxies. cmd/seed's own seedRoles comment
// already calls "admin" and "user" provisional placeholders; both get
// read access to the demo resource here because nothing about a
// read-only demo gives a reason to restrict an ordinary user from it —
// RF-05 is enforced (a role absent from this map, or without this
// permission, is refused) even though neither of the two roles that
// exist today is the one it refuses.
var gatewayRolePermissions = rbac.Permissions{
	"admin": {gatewayWidgetsReadPermission},
	"user":  {gatewayWidgetsReadPermission},
}

// userRoleLookup adapts identity.UserStore to proxy.RoleLookup —
// internal/proxy never imports internal/identity directly (its own
// package doc's boundary), so this small shim is where the two meet,
// the same role main.go already plays for every other pair of
// internal/ packages that must not import each other (ADR-0001).
type userRoleLookup struct {
	users identity.UserStore
}

func (l userRoleLookup) RoleOf(ctx context.Context, subject string) (string, error) {
	u, ok, err := l.users.ByID(ctx, subject)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("userRoleLookup: no user with id %q", subject)
	}
	return u.Role, nil
}

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

	// loginLimiter and authorizeLimiter share rateLimitStore by design
	// (WithStore's own doc comment), but sharing the bare IP key too would
	// collide them on one bucket: whichever route a client hit would spend
	// the other route's budget, collapsing RS-22's two deliberately
	// different tiers into one. namespacedKeyFunc keeps the shared store
	// while giving each limiter its own key space.
	loginLimiter := ratelimit.New(loginBurst, loginPerSecond, ratelimit.WithStore(rateLimitStore), ratelimit.WithKeyFunc(namespacedKeyFunc("login:", keyFunc)))
	authorizeLimiter := ratelimit.New(authorizeBurst, authorizePerSecond, ratelimit.WithStore(rateLimitStore), ratelimit.WithKeyFunc(namespacedKeyFunc("authorize:", keyFunc)))
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

	// #104: config.Load already validated this is an absolute URL when
	// GatewayAPIUpstream is set at all (empty means no gateway route);
	// re-parsing here, rather than threading a *url.URL through Config
	// itself, keeps internal/config's own Config a plain value type with
	// no net/url-specific field, the same reasoning cfg.Issuer (a string,
	// re-parsed where a *url.URL is actually needed) already follows.
	var gatewayUpstream *url.URL
	if cfg.GatewayAPIUpstream != "" {
		gatewayUpstream, err = url.Parse(cfg.GatewayAPIUpstream)
		if err != nil {
			return fmt.Errorf("parse USHER_API_UPSTREAM_URL: %w", err)
		}
	}

	deps := routerDeps{
		Authenticator:        authenticator,
		GatewayUpstream:      gatewayUpstream,
		GatewayAudience:      cfg.GatewayAPIAudience,
		GatewayPermission:    gatewayWidgetsReadPermission,
		GatewayRoles:         userRoleLookup{users: userStore},
		GatewayAuthorizer:    rbac.New(gatewayRolePermissions),
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

// namespacedKeyFunc prefixes whatever key fn derives (the client's IP, by
// REQUIREMENTS §7.2's own topology choice) so that limiters sharing one
// store do not share a bucket too. Without this, two limiters built with
// the same fn and the same WithStore collide: moat/ratelimit.Store.TakeN
// keys purely by the returned string, so a request against one route
// spends the other route's budget as well. A nil fn is never passed here,
// but errors still need to propagate rather than be swallowed into an
// empty key, which moat/ratelimit treats as an error of its own anyway.
func namespacedKeyFunc(prefix string, fn ratelimit.KeyFunc) ratelimit.KeyFunc {
	return func(r *http.Request) (string, error) {
		key, err := fn(r)
		if err != nil {
			return "", err
		}
		return prefix + key, nil
	}
}

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
