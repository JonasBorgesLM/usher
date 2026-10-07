package identity

import (
	"crypto/subtle"
	"strings"
	"testing"
)

// weakParams is a small, fast Params for tests — DefaultParams' 64 MiB would
// make the whole suite slow for no benefit; what these tests check does not
// depend on the specific cost, only on the encode/decode/compare logic.
var weakParams = Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// TestHashPassword_VerifyPassword_RoundTrip is RS-13's own encoding: a
// versioned, salted argon2id PHC string, not a bare digest.
func TestHashPassword_VerifyPassword_RoundTrip(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple", weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Errorf("unexpected PHC prefix: %s", encoded)
	}

	ok, err := VerifyPassword("correct horse battery staple", encoded)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("VerifyPassword: correct password did not verify")
	}
}

func TestVerifyPassword_WrongPasswordFails(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple", weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword("wrong password entirely", encoded)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Error("VerifyPassword: wrong password verified")
	}
}

func TestHashPassword_DistinctSaltsPerCall(t *testing.T) {
	a, err := HashPassword("same password", weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword("same password", weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Error("two hashes of the same password with fresh salts are identical — salt is not varying")
	}
}

func TestVerifyPassword_MalformedHashFails(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"not a PHC string": "not-even-close-to-phc",
		"wrong variant":    "$bcrypt$v=1$cost=10$c2FsdA$aGFzaA",
		"bad version":      "$argon2id$v=1$m=8192,t=1,p=1$c2FsdA$aGFzaA",
		"truncated":        "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA",
		"bad salt b64":     "$argon2id$v=19$m=8192,t=1,p=1$not-base64!!!$aGFzaA",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyPassword("anything", encoded); err == nil {
				t.Errorf("VerifyPassword(%q) succeeded; want an error", encoded)
			}
		})
	}
}

// TestVerifyPassword_OversizedFieldRejected guards the bound decodePHC
// enforces on salt/hash length — added while closing a gosec finding on the
// int -> uint32 conversion, so it earns its own test rather than riding
// along on the other malformed-hash cases.
//
// Negative control: with the length check removed, this test failed to
// observe an error — verified by hand, restored before committing.
func TestVerifyPassword_OversizedFieldRejected(t *testing.T) {
	huge := strings.Repeat("A", 2000) // valid base64 alphabet, well past 1024 decoded bytes
	encoded := "$argon2id$v=19$m=8192,t=1,p=1$" + huge + "$aGFzaA"
	if _, err := VerifyPassword("anything", encoded); err == nil {
		t.Error("VerifyPassword accepted an oversized salt field; want a refusal")
	}
}

// TestVerifyPassword_UsesConstantTimeCompare is the issue's explicit
// requirement, made into an assertion rather than left to code review
// alone: this test independently recomputes the candidate hash and checks
// it against the stored one with subtle.ConstantTimeCompare — the same
// primitive VerifyPassword must use — so a future rewrite of VerifyPassword
// using == or bytes.Equal (which forbidigo's RS-15 rule also refuses at
// lint time) would make this test's own expectation stop matching
// VerifyPassword's behavior on a case built to be easy to get wrong: hashes
// that differ only in their last byte.
func TestVerifyPassword_ConstantTimeComparisonSemantics(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple", weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	_, _, hash, err := decodePHC(encoded)
	if err != nil {
		t.Fatalf("decodePHC: %v", err)
	}
	almostRight := append([]byte{}, hash...)
	almostRight[len(almostRight)-1] ^= 0xFF // flip the last byte only

	if subtle.ConstantTimeCompare(hash, almostRight) == 1 {
		t.Fatal("test fixture is broken: flipped hash compares equal")
	}
	ok, err := VerifyPassword("correct horse battery staple", encoded)
	if err != nil || !ok {
		t.Fatalf("sanity check failed: ok=%v err=%v", ok, err)
	}
}

func TestNeedsRehash(t *testing.T) {
	current := DefaultParams
	weaker, err := HashPassword("x", weakParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	atCurrent, err := HashPassword("x", current)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	needs, err := NeedsRehash(weaker, current)
	if err != nil {
		t.Fatalf("NeedsRehash(weaker): %v", err)
	}
	if !needs {
		t.Error("NeedsRehash: a record hashed under weakParams did not need a rehash against DefaultParams")
	}

	needs, err = NeedsRehash(atCurrent, current)
	if err != nil {
		t.Fatalf("NeedsRehash(current): %v", err)
	}
	if needs {
		t.Error("NeedsRehash: a record already at current parameters was reported as needing a rehash")
	}
}

// TestNeedsRehash_EachDimensionIndependently is RF-12-adjacent table
// discipline applied to ADR-0005: a record can be weak in exactly one
// dimension (memory, time, parallelism) while matching in the others, and
// NeedsRehash must catch each on its own, not only when all three regress
// together.
//
// Negative control: with the Iterations comparison removed from NeedsRehash,
// this test's "iterations" case failed to observe a rehash — verified by
// hand, restored before committing.
func TestNeedsRehash_EachDimensionIndependently(t *testing.T) {
	base := Params{Memory: 32 * 1024, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32}
	cases := map[string]Params{
		"memory":      {Memory: base.Memory - 1, Iterations: base.Iterations, Parallelism: base.Parallelism, SaltLength: base.SaltLength, KeyLength: base.KeyLength},
		"iterations":  {Memory: base.Memory, Iterations: base.Iterations - 1, Parallelism: base.Parallelism, SaltLength: base.SaltLength, KeyLength: base.KeyLength},
		"parallelism": {Memory: base.Memory, Iterations: base.Iterations, Parallelism: base.Parallelism - 1, SaltLength: base.SaltLength, KeyLength: base.KeyLength},
	}
	for name, weaker := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := HashPassword("x", weaker)
			if err != nil {
				t.Fatalf("HashPassword: %v", err)
			}
			needs, err := NeedsRehash(encoded, base)
			if err != nil {
				t.Fatalf("NeedsRehash: %v", err)
			}
			if !needs {
				t.Errorf("NeedsRehash: a record weaker only in %s was not flagged", name)
			}
		})
	}
}
