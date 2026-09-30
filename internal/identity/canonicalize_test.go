package identity

import "testing"

func TestCanonicalizeIdentifier_CaseVariantsMatch(t *testing.T) {
	a := CanonicalizeIdentifier("Alice@Example.com")
	b := CanonicalizeIdentifier("alice@example.com")
	if a != b {
		t.Errorf("case variants did not canonicalize to the same value: %q != %q", a, b)
	}
}

// TestCanonicalizeIdentifier_UnicodeNormalizationVariantsMatch is the
// issue's own wording — "Unicode variants" — made concrete: the same
// visible identifier, encoded two different ways. "é" (U+00E9, a single
// precomposed code point) and "e" + a combining acute accent (U+0065
// U+0301) render identically and are different byte sequences.
//
// Negative control: with the norm.NFC.String call removed from
// CanonicalizeIdentifier (case folding alone, no normalization), this test
// failed — the two encodings folded to different strings. Verified by
// hand, restored before committing.
func TestCanonicalizeIdentifier_UnicodeNormalizationVariantsMatch(t *testing.T) {
	precomposed := "josé@example.com" // "josé" with é as U+00E9
	decomposed := "josé@example.com" // "jose" + combining acute accent (U+0301)
	if precomposed == decomposed {
		t.Fatal("test fixture is broken: the two byte sequences are already equal")
	}

	a := CanonicalizeIdentifier(precomposed)
	b := CanonicalizeIdentifier(decomposed)
	if a != b {
		t.Errorf("NFC/NFD variants did not canonicalize to the same value: %q != %q", a, b)
	}
}

// TestCanonicalizeIdentifier_SpecialCaseFoldingRules is the same property
// for a script simple ASCII lowering never sees: German "ß" full-case-folds
// to "ss", matching an identifier that was always typed with "ss".
//
// Negative control: with cases.Fold() replaced by strings.ToLower in
// CanonicalizeIdentifier, this test failed — ToLower leaves "ß" unchanged,
// so it never matched "ss". Verified by hand, restored before committing.
func TestCanonicalizeIdentifier_SpecialCaseFoldingRules(t *testing.T) {
	a := CanonicalizeIdentifier("straße@example.com") // "straße"
	b := CanonicalizeIdentifier("strasse@example.com")
	if a != b {
		t.Errorf("full case folding did not equate ß with ss: %q != %q", a, b)
	}
}

func TestCanonicalizeIdentifier_TrimsWhitespace(t *testing.T) {
	a := CanonicalizeIdentifier("  alice@example.com  ")
	b := CanonicalizeIdentifier("alice@example.com")
	if a != b {
		t.Errorf("leading/trailing whitespace was not trimmed: %q != %q", a, b)
	}
}

func TestCanonicalizeIdentifier_DistinctIdentifiersStayDistinct(t *testing.T) {
	a := CanonicalizeIdentifier("alice@example.com")
	b := CanonicalizeIdentifier("bob@example.com")
	if a == b {
		t.Error("two genuinely different identifiers canonicalized to the same value")
	}
}
