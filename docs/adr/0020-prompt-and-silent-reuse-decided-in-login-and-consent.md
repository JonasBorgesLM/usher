# ADR-0020: `prompt`/`max_age`'s silent-reuse decision lives in `/login` and `/consent`, not `/authorize`

## Status
Accepted — 2026-10-05

## Context
RF-11 asks for `prompt=none` ("error if interaction needed"), `prompt=login`
("force re-auth") and `max_age`. All three are meaningless without an answer
to "is interaction needed right now" — which means checking whether the
browser already carries a session (and, for consent, a prior grant) that
satisfies this specific request.

That check did not exist anywhere before this issue. RF-10 ("a second
`/authorize` from the same browser does not re-prompt within its lifetime")
was cited as done by #19, but #19 only built the session *mechanism* — the
`__Host-` cookie, `SessionStore`, idle/absolute lifetimes. Nothing read that
session back at `/authorize` or `/login` time; `/login`'s own `GET` handler
rendered the password form unconditionally, regardless of any existing
cookie. Implementing `prompt`/`max_age` honestly means building that
consultation for the first time, not layering a parameter switch on top of
behavior that was assumed to already exist.

Three places could own the decision:
1. **Inside `/authorize` itself**, before ever creating a `Challenge` — on a
   full silent hit, issue the code directly.
2. **Inside `/login` and `/consent`**, each deciding its own half (is the
   session fresh enough; is consent already granted) using the `Challenge`'s
   stored `Prompt`/`MaxAge` fields, the same way `/consent` already decides
   whether to skip its own form for a prior grant (RF-13).
3. **A narrower scope**: implement parameter validation now, defer the
   actual silent-completion behavior to a later issue.

## Decision
Option 2. `/authorize` only validates `prompt` (exactly `""`, `"none"` or
`"login"` — not OIDC Core's general space-delimited list) and `max_age`
(a non-negative integer of seconds), storing both on the `Challenge`
unchanged, the same way it already stores `Nonce` (ADR established by #44).

`/login`'s `GET` handler is where "is interaction needed" is actually
decided: it reads the browser's session cookie via the existing
`session.SessionStore`, and skips the form when the session is both present
and not stale under `max_age`, and `prompt` never asked for `login`. On a
skip, it records the session's own subject *and auth_time* on the challenge
(`ChallengeStore.SetAuthenticated`, replacing the narrower `SetSubject`) and
hands off to `/consent` exactly as a fresh password login already does.
`prompt=none` with no session (or a stale one) redirects `login_required` to
the client instead of rendering the form.

`/consent`'s own `serve` gains the parallel case: when it already renders a
form because consent is genuinely required and not yet granted, and
`Prompt == "none"`, it redirects `consent_required` instead.

`auth_time` (RF-11's other half, deferred by #44/#96 to this issue) is the
session's own `AuthTime` — carried from `Challenge` to `oauth.Code`
(`completeConsent`) to the `id_token` (`issueIDToken`) unchanged. A silent
reuse does not get a fresher `auth_time` than the login that actually
produced the session.

## The alternative that was rejected
**Deciding inside `/authorize` (option 1).** Concentrates the new logic in
one place and avoids touching two handlers instead of one. Rejected because:

- it breaks `/authorize`'s own stated character — its file doc comment says
  it "hands off to /login with a pending session.Challenge; login, consent
  and code issuance are later issues" — i.e. it was deliberately built to
  know nothing about session or consent state;
- it would need three new dependencies threaded into `authorizeHandler`
  (`Sessions`, `Consents`, `Codes`) that it has never needed before, and a
  duplicate (or extracted) copy of `consent.go`'s own code-issuance step for
  the full-silent-hit path;
- `/consent` already owns exactly this kind of decision for RF-13 (skip the
  form when a prior grant covers the request) — adding the equivalent
  session check to `/login` is consistent with an existing pattern, not a
  new one.

**Deferring silent completion (option 3)** was also considered and
rejected: `prompt=none`'s entire value is the success path OIDC Core
describes ("the End-User is already authenticated"), and shipping only the
error path would make the parameter supported in name but dead in practice
— indistinguishable, from a client's perspective, from `/login` always
requiring interaction, which was already true before this issue.

## Consequences
- `session.ChallengeStore.SetSubject` is renamed `SetAuthenticated` and
  gains an `authTime time.Time` parameter — its one real caller
  (`login.go`) is being changed for exactly this reason, the same
  "first real caller decides the signature" precedent `CreateFamily` (#37),
  the `logger` parameter (#40) and `ValidateRoute` (#41) already set.
- A browser can now reach `/token` with an access token and (for an
  `openid` request) an `id_token` without any human interaction at all,
  provided its session and consent already cover the request. This is the
  intended behavior RF-10/RF-11 describe, not a new attack surface beyond
  what an already-live, already-trusted session cookie already grants.
- `/login`'s `GET` handler now depends on `session.SessionStore`, which it
  already held (for `RotateLogin`'s pre-login cleanup) but had never read
  from before completing a password attempt.

## Reopening criterion
None stated. If a future requirement needs the fully-silent, zero-redirect
completion option 1 describes (skipping `/consent`'s own redirect hop
entirely on a full hit), reopen with a measured latency cost from the two
extra redirects as the trigger, not a preference alone.
