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
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/realip"
)

// Config is every operational setting Load produces.
type Config struct {
	DatabaseURL string
	RedisAddr   string

	// The seven lifetimes REQUIREMENTS RF-12 bounds. Each has a default used
	// when its environment variable is unset, and an upper bound a
	// configured value may not exceed — see lifetimeBounds below, which is
	// both this file's source of truth and the table its own tests iterate,
	// so a bound changed in one place cannot silently drift from the other.
	AuthCodeTTL        time.Duration // RS-04
	ChallengeTTL       time.Duration // RS-05
	AccessTokenTTL     time.Duration // RF-06's gateway-local revocation bound
	RefreshIdleTTL     time.Duration
	RefreshAbsoluteTTL time.Duration
	SessionIdleTTL     time.Duration // RS-31
	SessionAbsoluteTTL time.Duration // RS-31

	// TrustedProxyCIDRs and DirectlyExposed are ADR-0010's inbound trust
	// decision — who fronts usher itself, for the IP axis of RS-22 (and any
	// other realip-derived key). Exactly one of the two holds: an empty
	// CIDR list with DirectlyExposed false is a startup error (RNF-05),
	// the same shape moat's own preset.Config refuses for the same reason.
	TrustedProxyCIDRs []string
	DirectlyExposed   bool
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

	cfg := Config{DatabaseURL: dbURL, RedisAddr: redisAddr}

	for _, lb := range lifetimeBounds {
		d := lb.def
		if raw, ok := getenv(lb.env); ok && raw != "" {
			parsed, err := time.ParseDuration(raw)
			if err != nil {
				return Config{}, fmt.Errorf("config: %s (%s=%q) is not a valid duration: %w", lb.name, lb.env, raw, err)
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

	if raw, ok := getenv("USHER_TRUSTED_PROXY_CIDRS"); ok {
		for part := range strings.SplitSeq(raw, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				cfg.TrustedProxyCIDRs = append(cfg.TrustedProxyCIDRs, trimmed)
			}
		}
	}
	if raw, ok := getenv("USHER_DIRECTLY_EXPOSED"); ok {
		exposed, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("config: USHER_DIRECTLY_EXPOSED=%q is not a valid boolean: %w", raw, err)
		}
		cfg.DirectlyExposed = exposed
	}
	if len(cfg.TrustedProxyCIDRs) > 0 && cfg.DirectlyExposed {
		return Config{}, errors.New("config: USHER_TRUSTED_PROXY_CIDRS is set but USHER_DIRECTLY_EXPOSED is also set; pick one")
	}
	if len(cfg.TrustedProxyCIDRs) == 0 && !cfg.DirectlyExposed {
		return Config{}, errors.New("config: set USHER_TRUSTED_PROXY_CIDRS to your proxy's CIDRs, or USHER_DIRECTLY_EXPOSED=true if nothing fronts this server; without one the rate limiter's IP axis would count every client as the same client")
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
