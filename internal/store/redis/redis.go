// Package redis implements the interfaces REQUIREMENTS §7.1 puts in Redis —
// oauth.CodeStore, session.ChallengeStore, session.SessionStore,
// proxy.Denylist — over moat/redisstore, plus the RNF-07 eviction check
// asserted at startup. It is imported only from cmd/usher's wiring; no other
// package names its concrete types.
//
// Each Store implementation arrives with its own feature issue in M1, M2, M4
// and M6 (REQUIREMENTS §11). This file exists so the package is real for
// check-boundaries.sh and go build before that code is written.
package redis
