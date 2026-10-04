// Package config loads usher's operational settings from the environment
// (RNF-03) and fails closed on anything incomplete or out of bounds (RNF-05)
// — every "startup error" named elsewhere in docs/ARCHITECTURE.md (RF-01's
// client registry, RS-19's per-route audiences, RS-33's Argon2id memory
// ceiling, RNF-07's eviction check) is refused here, in one place, rather
// than discovered at the point each feature happens to check it.
//
// Load is the only place in this repository that reads an environment
// variable directly (TestOSEnvironmentIsReadOnlyInConfig enforces this
// mechanically). A later feature that needs a new setting adds it to Load,
// never a second os.Getenv call of its own.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/realip"
	"github.com/JonasBorgesLM/moat/secret"
)

// Config is every operational setting Load produces.
type Config struct {
	DatabaseURL string
	RedisAddr   string

	// Issuer is this AS's own identity (RS-29/RFC 9207): carried as `iss`
	// on every /authorize redirect, success or error, so a client talking
	// to more than one AS can tell them apart (T-04). An absolute URL, by
	// OIDC discovery's own convention for the issuer identifier.
	Issuer string

	// The eight lifetimes REQUIREMENTS RF-12 bounds. Each has a default used
	// when its environment variable is unset, and an upper bound a
	// configured value may not exceed — see lifetimeBounds below, which is
	// both this file's source of truth and the table its own tests iterate,
	// so a bound changed in one place cannot silently drift from the other.
	AuthCodeTTL          time.Duration // RS-04
	ChallengeTTL         time.Duration // RS-05
	AccessTokenTTL       time.Duration // RF-06's gateway-local revocation bound
	RefreshIdleTTL       time.Duration
	RefreshAbsoluteTTL   time.Duration
	SessionIdleTTL       time.Duration // RS-31
	SessionAbsoluteTTL   time.Duration // RS-31
	ConsumerJWKSCacheTTL time.Duration // RS-09's formula; also /.well-known/jwks.json's own Cache-Control max-age (#33)

	// TrustedProxyCIDRs and DirectlyExposed are ADR-0010's inbound trust
	// decision — who fronts usher itself, for the IP axis of RS-22 (and any
	// other realip-derived key). Exactly one of the two holds: an empty
	// CIDR list with DirectlyExposed false is a startup error (RNF-05),
	// the same shape moat's own preset.Config refuses for the same reason.
	TrustedProxyCIDRs []string
	DirectlyExposed   bool

	// RedisPassword authenticates to Redis (`--requirepass`, RNF-07's own
	// compose service sets one). Optional: "" is a valid Redis deployment
	// with no AUTH configured, not a misconfiguration this package can
	// detect from here.
	RedisPassword string

	// ListenAddr is the address cmd/usher's own http.Server binds (RNF-10).
	ListenAddr string

	// CSRFSecret is RS-12a's own signing key (moat/csrf.New), loaded once
	// at startup and held stable across restarts — regenerating it per
	// process would reject every token a previous process issued
	// (moat/csrf's own New doc comment). Hex-encoded on the wire, at least
	// csrf.MinSecretLen bytes decoded; never logged (RS-23), which is
	// exactly what wrapping it in secret.Value here, rather than handing
	// back a bare []byte, is for.
	CSRFSecret secret.Value

	// ClientsPath is RF-01's static client registry file, loaded by
	// identity.LoadClients. A path, not the parsed registry itself —
	// internal/config stays ignorant of internal/identity's own types,
	// the same boundary direction every other store-shaped setting here
	// already respects.
	ClientsPath string

	// KeysDir is ADR-0015's mounted signing keyset directory, loaded by
	// keys.Load.
	KeysDir string

	// HashConcurrency, HashWait and HashMemoryCeilingKiB are RS-33's own
	// three numbers: identity.NewHasher's slots, its per-slot wait before
	// giving up (identity.ErrSaturated), and the ceiling slots×params.Memory
	// may not exceed. REQUIREMENTS names the property, not a number —
	// these defaults (8 slots, 1 GiB ceiling) are this deployment's own
	// choice, not a requirement restated.
	HashConcurrency      int
	HashWait             time.Duration
	HashMemoryCeilingKiB uint64

	// CrierURL, CrierServiceName and CrierToken configure RI-03's audit
	// emitter. CrierURL == "" means no crier in this deployment — the
	// local docker-compose stack does not run one — and
	// routerDeps.Emitter is left nil ("nil emits nothing" is this
	// project's own established contract, not a special case to wire
	// around).
	CrierURL         string
	CrierServiceName string
	CrierToken       secret.Value
}

// lifetimeBound names one RF-12 lifetime: the environment variable that
// configures it, its default, its upper bound, and how to assign a parsed
// value onto a Config.
type lifetimeBound struct {
	name   string
	env    string
	def    time.Duration
	max    time.Duration
	assign func(*Config, time.Duration)
}

// lifetimeBounds is REQUIREMENTS RF-12's table, in code. Durations are
// expressed in hours rather than days because time.ParseDuration has no day
// unit — an operator setting USHER_REFRESH_ABSOLUTE_TTL writes "168h", not
// "7d".
var lifetimeBounds = []lifetimeBound{
	{
		name: "authorization code TTL", env: "USHER_AUTH_CODE_TTL",
		def: 60 * time.Second, max: 60 * time.Second,
		assign: func(c *Config, d time.Duration) { c.AuthCodeTTL = d },
	},
	{
		name: "login/consent challenge TTL", env: "USHER_CHALLENGE_TTL",
		def: 5 * time.Minute, max: 15 * time.Minute,
		assign: func(c *Config, d time.Duration) { c.ChallengeTTL = d },
	},
	{
		name: "access token TTL", env: "USHER_ACCESS_TOKEN_TTL",
		def: 5 * time.Minute, max: 15 * time.Minute,
		assign: func(c *Config, d time.Duration) { c.AccessTokenTTL = d },
	},
	{
		name: "refresh token idle TTL", env: "USHER_REFRESH_IDLE_TTL",
		def: 24 * time.Hour, max: 7 * 24 * time.Hour,
		assign: func(c *Config, d time.Duration) { c.RefreshIdleTTL = d },
	},
	{
		name: "refresh family absolute TTL", env: "USHER_REFRESH_ABSOLUTE_TTL",
		def: 7 * 24 * time.Hour, max: 30 * 24 * time.Hour,
		assign: func(c *Config, d time.Duration) { c.RefreshAbsoluteTTL = d },
	},
	{
		name: "browser session idle TTL", env: "USHER_SESSION_IDLE_TTL",
		def: 30 * time.Minute, max: 2 * time.Hour,
		assign: func(c *Config, d time.Duration) { c.SessionIdleTTL = d },
	},
	{
		name: "browser session absolute TTL", env: "USHER_SESSION_ABSOLUTE_TTL",
		def: 12 * time.Hour, max: 24 * time.Hour,
		assign: func(c *Config, d time.Duration) { c.SessionAbsoluteTTL = d },
	},
	{
		name: "consumer JWKS cache TTL", env: "USHER_CONSUMER_JWKS_CACHE_TTL",
		def: 10 * time.Minute, max: time.Hour,
		assign: func(c *Config, d time.Duration) { c.ConsumerJWKSCacheTTL = d },
	},
}

// Getenv abstracts os.LookupEnv so Load's own tests can supply an isolated
// environment instead of mutating the process's real one.
type Getenv func(key string) (value string, ok bool)

// FromOSEnv is the Getenv Load runs under in production — the one call site
// in this repository allowed to read the process environment directly.
func FromOSEnv(key string) (string, bool) { return os.LookupEnv(key) }

// Load reads every required and optional setting through getenv and returns
// the first violation it finds, rather than collecting all of them: RNF-05
// wants the process to refuse to start, not to print a diagnostic and start
// anyway.
func Load(getenv Getenv) (Config, error) {
	dbURL, ok := getenv("USHER_DATABASE_URL")
	if !ok || dbURL == "" {
		return Config{}, fmt.Errorf("config: USHER_DATABASE_URL is required and was not set")
	}
	redisAddr, ok := getenv("USHER_REDIS_ADDR")
	if !ok || redisAddr == "" {
		return Config{}, fmt.Errorf("config: USHER_REDIS_ADDR is required and was not set")
	}
	issuer, ok := getenv("USHER_ISSUER")
	if !ok || issuer == "" {
		return Config{}, fmt.Errorf("config: USHER_ISSUER is required and was not set")
	}
	issuerURL, err := url.Parse(issuer)
	if err != nil || !issuerURL.IsAbs() {
		return Config{}, fmt.Errorf("config: USHER_ISSUER=%q is not an absolute URL", issuer)
	}

	cfg := Config{DatabaseURL: dbURL, RedisAddr: redisAddr, Issuer: issuer}

	for _, lb := range lifetimeBounds {
		d := lb.def
		if rawLifetime, lifetimeSet := getenv(lb.env); lifetimeSet && rawLifetime != "" {
			parsed, parseErr := time.ParseDuration(rawLifetime)
			if parseErr != nil {
				return Config{}, fmt.Errorf("config: %s (%s=%q) is not a valid duration: %w", lb.name, lb.env, rawLifetime, parseErr)
			}
			d = parsed
		}
		if d <= 0 {
			return Config{}, fmt.Errorf("config: %s must be positive, got %s (%s)", lb.name, d, lb.env)
		}
		if d > lb.max {
			return Config{}, fmt.Errorf("config: %s is %s, which exceeds its bound of %s (%s)", lb.name, d, lb.max, lb.env)
		}
		lb.assign(&cfg, d)
	}

	if rawCIDRs, cidrsSet := getenv("USHER_TRUSTED_PROXY_CIDRS"); cidrsSet {
		for part := range strings.SplitSeq(rawCIDRs, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				cfg.TrustedProxyCIDRs = append(cfg.TrustedProxyCIDRs, trimmed)
			}
		}
	}
	if rawExposed, exposedSet := getenv("USHER_DIRECTLY_EXPOSED"); exposedSet {
		exposed, parseErr := strconv.ParseBool(rawExposed)
		if parseErr != nil {
			return Config{}, fmt.Errorf("config: USHER_DIRECTLY_EXPOSED=%q is not a valid boolean: %w", rawExposed, parseErr)
		}
		cfg.DirectlyExposed = exposed
	}
	if len(cfg.TrustedProxyCIDRs) > 0 && cfg.DirectlyExposed {
		return Config{}, errors.New("config: USHER_TRUSTED_PROXY_CIDRS is set but USHER_DIRECTLY_EXPOSED is also set; pick one")
	}
	if len(cfg.TrustedProxyCIDRs) == 0 && !cfg.DirectlyExposed {
		return Config{}, errors.New("config: set USHER_TRUSTED_PROXY_CIDRS to your proxy's CIDRs, or USHER_DIRECTLY_EXPOSED=true if nothing fronts this server; without one the rate limiter's IP axis would count every client as the same client")
	}

	if redisPassword, redisPasswordSet := getenv("USHER_REDIS_PASSWORD"); redisPasswordSet {
		cfg.RedisPassword = redisPassword
	}

	cfg.ListenAddr = ":8080"
	if addr, addrSet := getenv("USHER_ADDR"); addrSet && addr != "" {
		cfg.ListenAddr = addr
	}

	csrfSecretHex, ok := getenv("USHER_CSRF_SECRET")
	if !ok || csrfSecretHex == "" {
		return Config{}, fmt.Errorf("config: USHER_CSRF_SECRET is required and was not set")
	}
	csrfSecretBytes, err := hex.DecodeString(csrfSecretHex)
	if err != nil {
		return Config{}, fmt.Errorf("config: USHER_CSRF_SECRET is not valid hex: %w", err)
	}
	if len(csrfSecretBytes) < csrf.MinSecretLen {
		return Config{}, fmt.Errorf("config: USHER_CSRF_SECRET decodes to %d bytes, want at least %d (csrf.MinSecretLen)", len(csrfSecretBytes), csrf.MinSecretLen)
	}
	cfg.CSRFSecret = secret.New(csrfSecretBytes)

	clientsPath, ok := getenv("USHER_CLIENTS_PATH")
	if !ok || clientsPath == "" {
		return Config{}, fmt.Errorf("config: USHER_CLIENTS_PATH is required and was not set")
	}
	cfg.ClientsPath = clientsPath

	keysDir, ok := getenv("USHER_KEYS_DIR")
	if !ok || keysDir == "" {
		return Config{}, fmt.Errorf("config: USHER_KEYS_DIR is required and was not set")
	}
	cfg.KeysDir = keysDir

	cfg.HashConcurrency = 8
	if rawConcurrency, concurrencySet := getenv("USHER_HASH_CONCURRENCY"); concurrencySet && rawConcurrency != "" {
		n, convErr := strconv.Atoi(rawConcurrency)
		if convErr != nil || n <= 0 {
			return Config{}, fmt.Errorf("config: USHER_HASH_CONCURRENCY=%q must be a positive integer", rawConcurrency)
		}
		cfg.HashConcurrency = n
	}

	cfg.HashWait = 500 * time.Millisecond
	if rawWait, waitSet := getenv("USHER_HASH_WAIT"); waitSet && rawWait != "" {
		d, parseErr := time.ParseDuration(rawWait)
		if parseErr != nil || d <= 0 {
			return Config{}, fmt.Errorf("config: USHER_HASH_WAIT=%q must be a positive duration", rawWait)
		}
		cfg.HashWait = d
	}

	cfg.HashMemoryCeilingKiB = 1 << 20 // 1 GiB
	if rawCeiling, ceilingSet := getenv("USHER_HASH_MEMORY_CEILING_KIB"); ceilingSet && rawCeiling != "" {
		n, convErr := strconv.ParseUint(rawCeiling, 10, 64)
		if convErr != nil || n == 0 {
			return Config{}, fmt.Errorf("config: USHER_HASH_MEMORY_CEILING_KIB=%q must be a positive integer", rawCeiling)
		}
		cfg.HashMemoryCeilingKiB = n
	}

	// Crier is entirely optional (RI-03): this deployment's own
	// docker-compose stack does not run one. CrierURL == "" is read
	// downstream as "no audit emitter," never as a malformed one.
	if crierURL, crierURLSet := getenv("USHER_CRIER_URL"); crierURLSet {
		cfg.CrierURL = crierURL
	}
	if cfg.CrierURL != "" {
		serviceName, serviceNameSet := getenv("USHER_CRIER_SERVICE_NAME")
		if !serviceNameSet || serviceName == "" {
			return Config{}, fmt.Errorf("config: USHER_CRIER_URL is set but USHER_CRIER_SERVICE_NAME was not")
		}
		cfg.CrierServiceName = serviceName

		tokenRaw, tokenSet := getenv("USHER_CRIER_TOKEN")
		if !tokenSet || tokenRaw == "" {
			return Config{}, fmt.Errorf("config: USHER_CRIER_URL is set but USHER_CRIER_TOKEN was not")
		}
		cfg.CrierToken = secret.New([]byte(tokenRaw))
	}

	return cfg, nil
}

// BuildKeyFunc derives a moat/ratelimit.KeyFunc from the validated trust
// topology (ADR-0010, RS-22's IP axis): realip.New(c.TrustedProxyCIDRs)'s
// KeyFunc when proxy CIDRs are declared, or ratelimit.RemoteAddrKey — moat's
// own default, which reads r.RemoteAddr directly and never consults a
// forwarded header — when DirectlyExposed is set instead.
//
// Load already guarantees exactly one of the two holds, so BuildKeyFunc
// itself has nothing left to validate; it exists so that whichever
// middleware chain wires the IP axis (REQUIREMENTS §7.2) does not re-derive
// this choice, or its consequences, on its own.
func (c Config) BuildKeyFunc() (ratelimit.KeyFunc, error) {
	if c.DirectlyExposed {
		return ratelimit.RemoteAddrKey, nil
	}
	extractor, err := realip.New(c.TrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("config: build trusted-proxy extractor: %w", err)
	}
	return extractor.KeyFunc(), nil
}
