// Package config loads usher's operational settings from the environment and
// versioned files (RNF-03) and fails closed on anything incomplete or out of
// bounds (RNF-05) — every "startup error" named elsewhere in
// docs/ARCHITECTURE.md (RF-01's client registry, RF-12's lifetime bounds,
// RS-19's per-route audiences, RS-33's Argon2id memory ceiling, RNF-07's
// eviction check) is refused here, in one place, rather than discovered at
// the point each feature happens to check it.
//
// Its Config type and loader are designed and implemented in M1 (issue #12,
// REQUIREMENTS §11) — this file exists so the package is real for
// check-boundaries.sh and go build before that design is written, not to
// anticipate it.
package config
