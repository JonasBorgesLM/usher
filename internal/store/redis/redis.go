// Package redis implements the interfaces REQUIREMENTS §7.1 puts in Redis —
// oauth.CodeStore, session.ChallengeStore, session.SessionStore,
// proxy.Denylist — over moat/redisstore. It is imported only from cmd/usher's
// wiring; no other package names its concrete types.
//
// NewRateLimitStore (RNF-07's eviction check, issue #18) is this package's
// own scope; each remaining Store implementation arrives with its own
// feature issue in M2, M4 and M6 (REQUIREMENTS §11).
package redis
