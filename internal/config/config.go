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
	"fmt"
	"os"
	"time"
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

	return cfg, nil
}
