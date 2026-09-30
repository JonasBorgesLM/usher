package identity

import (
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// foldCase performs locale-independent Unicode case folding — not a simple
// per-rune lowercase, which does not handle every script's casing rules
// correctly (German "ß", for one).
var foldCase = cases.Fold()

// CanonicalizeIdentifier reduces identifier to the one form used everywhere
// it is compared: UserStore lookup, the RS-22 per-account rate-limit key,
// and audit (RS-35). Two spellings of one identifier — different case, or
// the same visible text in a different Unicode normalization form — must
// resolve to the same account and the same rate-limit bucket, or the
// account axis is bypassed by whichever difference nothing else
// normalizes.
//
// Order matters, and each step closes a distinct way two strings can look
// identical and compare unequal:
//  1. Whitespace is trimmed first — a leading or trailing space is a
//     copy-paste accident, unrelated to case or encoding.
//  2. NFC normalization next, so a precomposed character ("é" as one code
//     point) and its decomposed equivalent ("e" + a combining acute
//     accent) — visually identical, byte-different — compare equal.
//  3. Case folding last, once the text is in one normalization form, so
//     folding sees a consistent input.
//
// Called once, at the boundary where a raw identifier enters the system —
// Authenticator.Attempt for a login attempt, and wherever a user record is
// created — never re-derived ad hoc at a third call site.
func CanonicalizeIdentifier(identifier string) string {
	trimmed := strings.TrimSpace(identifier)
	normalized := norm.NFC.String(trimmed)
	return foldCase.String(normalized)
}
