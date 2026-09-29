# ADR-0003: Rate limiting fails closed, and `noeviction` is an infrastructure requirement

## Status
Accepted — 2026-09-29

## Context
Rate limiting on the credential routes is the mitigation for credential
stuffing, enumeration and resource exhaustion (T-09, T-10, T-15). Its state is
in Redis. Two ways it fails without anyone noticing:

1. **Redis is unreachable.** A limiter that fails open lets everything through
   exactly when the infrastructure is degraded — which an attacker can often
   cause.
2. **Redis evicts keys.** Under `maxmemory` with any eviction policy, Redis
   drops buckets without knowing what they are, and the bucket of a client
   already being throttled — which makes no requests while blocked — is the
   best candidate under any recency- or TTL-based policy. The throttle lifts
   itself.

## Decision
- A limiter error denies the request (RNF-04). On the credential routes that
  is a `503`, never a pass.
- Redis must run with `maxmemory-policy noeviction`. usher asserts it at
  startup through `redisstore`'s `EvictionCheck()` and refuses to start unless
  the result is `Verified()` — *not checked* is a failure, not a pass (RNF-05,
  RNF-07).
- The compose file configures `noeviction` explicitly.

## The alternative that was rejected
**Fail open on the proxied read routes.** Arguably right for `/api/**` reads,
where a limiter outage causing an API outage is a poor trade. Rejected for the
MVP because the rule "infrastructure failure denies" is only auditable if it has
no exceptions; an exception is added by a later ADR with the route named, not by
a flag.

## Consequences
- A Redis outage is a login and token outage. That is the intended trade.
- Managed Redis offerings that block `CONFIG GET` (ElastiCache, MemoryDB,
  Upstash, Azure Cache) cannot run usher without a code change. That is
  deliberate: those are precisely the environments where the policy cannot be
  verified.
- The check is a snapshot at construction; a policy changed at runtime is not
  seen (RNF-07's accepted gap, T-16's residual).
