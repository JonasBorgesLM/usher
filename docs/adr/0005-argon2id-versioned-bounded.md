# ADR-0005: Argon2id with parameters versioned per record, under a concurrency bound

## Status
Accepted — 2026-09-29

## Context
Password hashes must resist offline cracking after a database dump (RS-13), and
the parameters that make that true today will be too weak in a few years. At
the same time, the hash runs on an unauthenticated endpoint, and a memory-hard
function is a memory-exhaustion lever there (RS-33).

## Decision
- `golang.org/x/crypto/argon2`, Argon2id.
- Each record stores its algorithm and parameters in PHC string format
  (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`). On a successful login whose record
  is below the current parameters, the password is re-hashed and the record
  updated — transparently, without a migration.
- Hashing runs behind a fixed-size semaphore. The budget
  `slots × m` is compared at startup against a configured memory ceiling; a
  configuration that exceeds it refuses to start (RS-33).
- The dummy hash used for non-existent users (RS-14) is computed at startup
  with the *current* parameters, so the non-existent path costs what the
  existing path costs.

## The alternative that was rejected
**bcrypt with a calibrated cost.** Simpler, no memory tuning, and not a
memory-exhaustion lever. Rejected because it is not memory-hard, so GPU and
ASIC cracking are far cheaper per guess, and because its 72-byte input limit is
a silent truncation to document around. The concurrency bound removes most of
Argon2id's operational downside.

## Consequences
- Under a login flood, legitimate users queue for slots and some get `503`.
  That is availability traded for survival of the process (T-15's residual).
- The saturation path must do equal work for existing and non-existent
  accounts, or queueing time becomes the enumeration oracle RS-14 closes.
- Parameter changes are configuration plus a rehash-on-login, never a bulk
  migration — so weak hashes of dormant accounts stay weak until they log in.
