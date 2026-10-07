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
// testCSRFSecretHex is 32 random bytes, hex-encoded -- a fixed test
// placeholder (#nosec G101), long enough to satisfy csrf.MinSecretLen.
const testCSRFSecretHex = "7624fe19b0cddddd511df7e8def3c87f2fafa9f288b231a5b05dd10b13abe858" // #nosec G101 -- fixed test placeholder, not a real credential

func validEnv() map[string]string {
	return map[string]string{ // #nosec G101 -- fixed test placeholder, not a real credential
		"USHER_DATABASE_URL":     "postgres://usher:usher@localhost:5432/usher",
		"USHER_REDIS_ADDR":       "localhost:6379",
		"USHER_ISSUER":           "https://usher.example.test",
		"USHER_DIRECTLY_EXPOSED": "true",
		"USHER_CSRF_SECRET":      testCSRFSecretHex,
		"USHER_CLIENTS_PATH":     "/etc/usher/clients.json",
		"USHER_KEYS_DIR":         "/etc/usher/keys",
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
	for _, key := range []string{"USHER_DATABASE_URL", "USHER_REDIS_ADDR", "USHER_ISSUER", "USHER_CSRF_SECRET", "USHER_CLIENTS_PATH", "USHER_KEYS_DIR"} {
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

// TestLoad_IssuerMustBeAbsoluteURL is RS-29's own prerequisite: iss is
// meaningless if it is not even a well-formed issuer identifier.
//
// Negative control: with the `!issuerURL.IsAbs()` half of Load's check
// removed, this test failed — a relative USHER_ISSUER loaded successfully.
// Verified by hand, restored before committing.
func TestLoad_IssuerMustBeAbsoluteURL(t *testing.T) {
	for _, bad := range []string{"not-a-url", "/relative/path", "usher.example.test"} {
		env := validEnv()
		env["USHER_ISSUER"] = bad
		if _, err := Load(mapGetenv(env)); err == nil {
			t.Errorf("Load succeeded with USHER_ISSUER=%q, want an error", bad)
		}
	}
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

// TestLoad_TrustTopologyMustBeExactlyOneOf is ADR-0010's rule made
// mechanical, the same shape moat's own preset.Config refuses for the same
// reason: exactly one of "which CIDRs front this server" or "nothing does"
// must be stated, never both and never neither.
//
// Negative control: with the `len(cfg.TrustedProxyCIDRs) == 0 &&
// !cfg.DirectlyExposed` check removed, this test's "neither set" case
// succeeded instead of refusing — verified by hand, restored before
// committing.
func TestLoad_TrustTopologyMustBeExactlyOneOf(t *testing.T) {
	t.Run("neither set", func(t *testing.T) {
		env := validEnv()
		delete(env, "USHER_DIRECTLY_EXPOSED")
		if _, err := Load(mapGetenv(env)); err == nil {
			t.Fatal("Load succeeded with no trust topology declared; want an error")
		}
	})

	t.Run("both set", func(t *testing.T) {
		env := validEnv()
		env["USHER_TRUSTED_PROXY_CIDRS"] = "10.0.0.0/8"
		// USHER_DIRECTLY_EXPOSED is already "true" from validEnv.
		if _, err := Load(mapGetenv(env)); err == nil {
			t.Fatal("Load succeeded with both CIDRs and DirectlyExposed set; want an error")
		}
	})
}

func TestLoad_TrustedProxyCIDRsParsed(t *testing.T) {
	env := validEnv()
	delete(env, "USHER_DIRECTLY_EXPOSED")
	env["USHER_TRUSTED_PROXY_CIDRS"] = " 10.0.0.0/8 , 172.28.0.0/24 ,,"

	cfg, err := Load(mapGetenv(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"10.0.0.0/8", "172.28.0.0/24"}
	if len(cfg.TrustedProxyCIDRs) != len(want) {
		t.Fatalf("TrustedProxyCIDRs = %v, want %v", cfg.TrustedProxyCIDRs, want)
	}
	for i, w := range want {
		if cfg.TrustedProxyCIDRs[i] != w {
			t.Errorf("TrustedProxyCIDRs[%d] = %q, want %q", i, cfg.TrustedProxyCIDRs[i], w)
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

// TestLoad_CSRFSecretMustDecodeToAtLeastMinSecretLen is RS-12a's own
// prerequisite: moat/csrf.New refuses a key shorter than MinSecretLen,
// and refusing it here, at startup, is RNF-05's "fails closed" applied
// before ever reaching that constructor.
//
// Negative control: with the `len(csrfSecretBytes) < csrf.MinSecretLen`
// check removed from Load, this test failed -- a 1-byte secret loaded
// successfully. Verified by hand, restored before committing.
func TestLoad_CSRFSecretMustDecodeToAtLeastMinSecretLen(t *testing.T) {
	env := validEnv()
	env["USHER_CSRF_SECRET"] = "ab" // one byte, hex-encoded
	if _, err := Load(mapGetenv(env)); err == nil {
		t.Fatal("Load succeeded with a 1-byte CSRF secret; want an error")
	}
}

func TestLoad_CSRFSecretMustBeValidHex(t *testing.T) {
	env := validEnv()
	env["USHER_CSRF_SECRET"] = "not-hex-at-all"
	if _, err := Load(mapGetenv(env)); err == nil {
		t.Fatal("Load succeeded with a non-hex CSRF secret; want an error")
	}
}

// TestLoad_HashConcurrencyDefaultAndOverride is RS-33's own three numbers,
// confirmed to have sane defaults and to be overridable.
func TestLoad_HashConcurrencyDefaultAndOverride(t *testing.T) {
	cfg, err := Load(mapGetenv(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HashConcurrency <= 0 {
		t.Errorf("HashConcurrency default = %d, want > 0", cfg.HashConcurrency)
	}
	if cfg.HashWait <= 0 {
		t.Errorf("HashWait default = %s, want > 0", cfg.HashWait)
	}
	if cfg.HashMemoryCeilingKiB == 0 {
		t.Errorf("HashMemoryCeilingKiB default = %d, want > 0", cfg.HashMemoryCeilingKiB)
	}

	env := validEnv()
	env["USHER_HASH_CONCURRENCY"] = "16"
	cfg, err = Load(mapGetenv(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HashConcurrency != 16 {
		t.Errorf("HashConcurrency = %d, want 16", cfg.HashConcurrency)
	}
}

func TestLoad_HashConcurrencyMustBePositive(t *testing.T) {
	env := validEnv()
	env["USHER_HASH_CONCURRENCY"] = "0"
	if _, err := Load(mapGetenv(env)); err == nil {
		t.Fatal("Load succeeded with USHER_HASH_CONCURRENCY=0; want an error")
	}
}

// TestLoad_CrierTokenRequiredWhenCrierURLSet is RI-03 applied at
// startup: a half-configured crier integration (a URL with no
// credential, or vice versa) fails closed rather than sending
// unauthenticated requests or silently running without one.
//
// Negative control: with the `cfg.CrierServiceName`/`cfg.CrierToken`
// requiredness checks removed from Load's `if cfg.CrierURL != ""`
// branch, this test failed -- Load succeeded with USHER_CRIER_URL set
// and neither companion variable present. Verified by hand, restored
// before committing.
func TestLoad_CrierTokenRequiredWhenCrierURLSet(t *testing.T) {
	env := validEnv()
	env["USHER_CRIER_URL"] = "https://crier.example.test"
	if _, err := Load(mapGetenv(env)); err == nil {
		t.Fatal("Load succeeded with USHER_CRIER_URL set but neither USHER_CRIER_SERVICE_NAME nor USHER_CRIER_TOKEN; want an error")
	}
}

func TestLoad_CrierUnsetByDefault(t *testing.T) {
	cfg, err := Load(mapGetenv(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CrierURL != "" {
		t.Errorf("CrierURL = %q, want empty when unset", cfg.CrierURL)
	}
}

// TestLoad_GatewayAudienceRequiredWhenUpstreamSet is RS-19 applied at
// startup, the same shape TestLoad_CrierTokenRequiredWhenCrierURLSet
// already proves for crier: a gateway upstream with no audience fails
// closed rather than silently proxying with the audience check skipped.
//
// Negative control: with the `cfg.GatewayAPIAudience` requiredness check
// removed from Load's `if cfg.GatewayAPIUpstream != ""` branch, this test
// failed -- Load succeeded with USHER_API_UPSTREAM_URL set and no
// USHER_API_UPSTREAM_AUDIENCE. Verified by hand, restored before
// committing.
func TestLoad_GatewayAudienceRequiredWhenUpstreamSet(t *testing.T) {
	env := validEnv()
	env["USHER_API_UPSTREAM_URL"] = "http://resource-server:8081"
	if _, err := Load(mapGetenv(env)); err == nil {
		t.Fatal("Load succeeded with USHER_API_UPSTREAM_URL set but no USHER_API_UPSTREAM_AUDIENCE; want an error")
	}
}

func TestLoad_GatewayUpstreamMustBeAbsoluteURL(t *testing.T) {
	env := validEnv()
	env["USHER_API_UPSTREAM_URL"] = "not-a-url"
	env["USHER_API_UPSTREAM_AUDIENCE"] = "https://resource-server.usher.local"
	if _, err := Load(mapGetenv(env)); err == nil {
		t.Fatal("Load succeeded with USHER_API_UPSTREAM_URL=\"not-a-url\"; want an error")
	}
}

func TestLoad_GatewayUnsetByDefault(t *testing.T) {
	cfg, err := Load(mapGetenv(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GatewayAPIUpstream != "" || cfg.GatewayAPIAudience != "" {
		t.Errorf("GatewayAPIUpstream = %q, GatewayAPIAudience = %q, want both empty when unset", cfg.GatewayAPIUpstream, cfg.GatewayAPIAudience)
	}
}

func TestLoad_GatewaySetTogether(t *testing.T) {
	env := validEnv()
	env["USHER_API_UPSTREAM_URL"] = "http://resource-server:8081"
	env["USHER_API_UPSTREAM_AUDIENCE"] = "https://resource-server.usher.local"
	cfg, err := Load(mapGetenv(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GatewayAPIUpstream != "http://resource-server:8081" {
		t.Errorf("GatewayAPIUpstream = %q, want %q", cfg.GatewayAPIUpstream, "http://resource-server:8081")
	}
	if cfg.GatewayAPIAudience != "https://resource-server.usher.local" {
		t.Errorf("GatewayAPIAudience = %q, want %q", cfg.GatewayAPIAudience, "https://resource-server.usher.local")
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
	case "USHER_CONSUMER_JWKS_CACHE_TTL":
		return cfg.ConsumerJWKSCacheTTL
	default:
		panic("lifetimeValue: unhandled lifetimeBound " + lb.env)
	}
}
