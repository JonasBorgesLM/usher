package config

import (
	"strings"
	"testing"
	"time"
)

// mapGetenv builds a Getenv over a fixed map, for tests that want an
// isolated environment rather than the process's real one.
func mapGetenv(env map[string]string) Getenv {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// validEnv is a complete, in-bounds environment every test starts from and
// mutates one key at a time — so a failing case is attributable to the one
// thing it changed, not to an incidentally-also-broken baseline.
func validEnv() map[string]string {
	return map[string]string{ // #nosec G101 -- fixed test placeholder, not a real credential
		"USHER_DATABASE_URL": "postgres://usher:usher@localhost:5432/usher",
		"USHER_REDIS_ADDR":   "localhost:6379",
	}
}

func TestLoad_ValidEnvironmentSucceeds(t *testing.T) {
	cfg, err := Load(mapGetenv(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DatabaseURL == "" || cfg.RedisAddr == "" {
		t.Errorf("required fields not populated: %+v", cfg)
	}
}

func TestLoad_DefaultsApplyWhenLifetimesUnset(t *testing.T) {
	cfg, err := Load(mapGetenv(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, lb := range lifetimeBounds {
		got := lifetimeValue(cfg, lb)
		if got != lb.def {
			t.Errorf("%s: got %s, want default %s", lb.name, got, lb.def)
		}
	}
}

// TestLoad_MissingRequiredField is RNF-05's own claim: an incomplete
// configuration refuses to start. Table-driven over both required fields
// rather than one hand-picked case, so adding a third required field without
// a matching test case here is a gap this test would otherwise hide.
func TestLoad_MissingRequiredField(t *testing.T) {
	for _, key := range []string{"USHER_DATABASE_URL", "USHER_REDIS_ADDR"} {
		t.Run(key, func(t *testing.T) {
			env := validEnv()
			delete(env, key)
			_, err := Load(mapGetenv(env))
			if err == nil {
				t.Fatalf("Load succeeded with %s missing; want an error", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not name the missing key %s", err, key)
			}
		})
	}

	t.Run("empty value counts as missing", func(t *testing.T) {
		env := validEnv()
		env["USHER_DATABASE_URL"] = ""
		if _, err := Load(mapGetenv(env)); err == nil {
			t.Fatal("Load succeeded with an empty USHER_DATABASE_URL; want an error")
		}
	})
}

// TestLoad_LifetimeAboveBoundFails is RF-12's bound, tested against
// lifetimeBounds itself rather than a hand-written duplicate of it — the
// same table Load parses is what this test walks, so a bound changed in one
// place cannot silently stop being tested.
//
// Negative control: with the `d > lb.max` check in Load commented out, this
// test was run and failed to observe an error for every case — verified by
// hand while writing this test, not left as an assertion nobody watched go
// red.
func TestLoad_LifetimeAboveBoundFails(t *testing.T) {
	for _, lb := range lifetimeBounds {
		t.Run(lb.name, func(t *testing.T) {
			env := validEnv()
			env[lb.env] = (lb.max + time.Second).String()
			_, err := Load(mapGetenv(env))
			if err == nil {
				t.Fatalf("Load succeeded with %s set to %s (bound is %s); want an error",
					lb.env, lb.max+time.Second, lb.max)
			}
		})
	}
}

func TestLoad_LifetimeAtExactBoundSucceeds(t *testing.T) {
	for _, lb := range lifetimeBounds {
		t.Run(lb.name, func(t *testing.T) {
			env := validEnv()
			env[lb.env] = lb.max.String()
			cfg, err := Load(mapGetenv(env))
			if err != nil {
				t.Fatalf("Load failed at the exact bound %s: %v", lb.max, err)
			}
			if got := lifetimeValue(cfg, lb); got != lb.max {
				t.Errorf("%s: got %s, want %s", lb.name, got, lb.max)
			}
		})
	}
}

func TestLoad_NonPositiveLifetimeFails(t *testing.T) {
	for _, raw := range []string{"0s", "-1s"} {
		for _, lb := range lifetimeBounds {
			t.Run(lb.name+"/"+raw, func(t *testing.T) {
				env := validEnv()
				env[lb.env] = raw
				if _, err := Load(mapGetenv(env)); err == nil {
					t.Fatalf("Load succeeded with %s=%s; want an error", lb.env, raw)
				}
			})
		}
	}
}

func TestLoad_MalformedDurationFails(t *testing.T) {
	env := validEnv()
	env["USHER_ACCESS_TOKEN_TTL"] = "not-a-duration"
	_, err := Load(mapGetenv(env))
	if err == nil {
		t.Fatal("Load succeeded with a malformed duration; want an error")
	}
	if !strings.Contains(err.Error(), "USHER_ACCESS_TOKEN_TTL") {
		t.Errorf("error %q does not name the offending variable", err)
	}
}

// lifetimeValue reads the Config field lb identifies, by its environment
// variable name -- lb.assign is a setter with no matching getter, so this is
// the read-side counterpart the tests above need.
func lifetimeValue(cfg Config, lb lifetimeBound) time.Duration {
	switch lb.env {
	case "USHER_AUTH_CODE_TTL":
		return cfg.AuthCodeTTL
	case "USHER_CHALLENGE_TTL":
		return cfg.ChallengeTTL
	case "USHER_ACCESS_TOKEN_TTL":
		return cfg.AccessTokenTTL
	case "USHER_REFRESH_IDLE_TTL":
		return cfg.RefreshIdleTTL
	case "USHER_REFRESH_ABSOLUTE_TTL":
		return cfg.RefreshAbsoluteTTL
	case "USHER_SESSION_IDLE_TTL":
		return cfg.SessionIdleTTL
	case "USHER_SESSION_ABSOLUTE_TTL":
		return cfg.SessionAbsoluteTTL
	default:
		panic("lifetimeValue: unhandled lifetimeBound " + lb.env)
	}
}
