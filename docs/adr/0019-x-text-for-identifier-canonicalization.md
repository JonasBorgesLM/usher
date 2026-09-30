# ADR-0019: `golang.org/x/text` for identifier canonicalization (NFC + case folding)

## Status
Accepted — 2026-09-30

## Context
RS-35 requires one canonical form of the login identifier — the same form
used for lookup, the per-account rate-limit key, and audit — so that two
spellings of one identifier never split into two buckets. Case is one way
two strings can look identical and compare unequal; Unicode normalization
form is another, and it has no standard-library answer: `strings.ToLower`
lowers rune by rune and does not reconcile a precomposed character (`"é"` as
one code point, U+00E9) with its decomposed equivalent (`"e"` followed by a
combining acute accent, U+0065 U+0301) — visually identical, byte-different,
and exactly the kind of pair RS-35's "Unicode variants" wording names.

## Decision
`golang.org/x/text/unicode/norm` (NFC normalization) and
`golang.org/x/text/cases` (locale-independent full case folding, not a
simple per-rune lowercase — it handles casing rules `strings.ToLower` does
not, such as German `"ß"`) in `identity.CanonicalizeIdentifier`: trim
whitespace, normalize to NFC, then fold case, in that order. Called once, at
the two points a raw identifier enters the system — `Authenticator.Attempt`
and user creation — never re-derived at a third call site.

`golang.org/x/text` was already present as an indirect dependency (pulled in
transitively); this promotes it to direct, with this ADR as its
justification for the allow-list (RNF-02, RNF-09).

## The alternative that was rejected
**`strings.ToLower` alone, no normalization step.** Covers ordinary ASCII
case differences — most of what a real deployment will ever see — for free,
with no dependency. Rejected because it does not satisfy RS-35's own
wording: two NFC/NFD encodings of a visibly identical identifier would still
compare unequal, which is precisely the "Unicode variant" the requirement
names, not a case difference `strings.ToLower` would have caught anyway.

## Consequences
- One more direct dependency, already present transitively, so this changes
  the allow-list and the trust boundary drawn around it, not the module
  graph's actual shape.
- Case folding is more aggressive than most users will ever notice — an
  identifier containing `"ß"` canonicalizes to contain `"ss"`, matching an
  identifier that was typed with `"ss"` to begin with. Accepted: the
  alternative is a per-script exception list, which is worse.
- Canonicalization happens in application code, not in the database. A
  value written by anything other than this project's own call sites
  (a manual `INSERT`, a future import tool) is not guaranteed canonical, and
  the schema's `UNIQUE` constraint on `identifier` (0001_initial_schema.sql)
  would then admit two rows for what a human reads as one address.
