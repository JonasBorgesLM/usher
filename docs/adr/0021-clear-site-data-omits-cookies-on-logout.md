# ADR-0021: `/logout`'s `Clear-Site-Data` omits `cookies` — `cache` and `storage` only

## Status
Accepted — 2026-10-06

## Context
RS-27 asks for `secureheaders.ClearSiteData` on `/logout`, defense in depth
on top of RS-31's own server-side session deletion. `moat/secureheaders`'s
own documentation for `ClearSiteData` flags one specific choice as worth
making deliberately rather than inheriting a default: its `SiteDataCookies`
directive clears cookies for the **registrable domain**, not this origin.
Logging out of `usher`, if it ever shares a registrable domain with another
application — a client app, a resource server, an unrelated service on the
same company domain — would also clear *that* application's cookies, logging
the user out of it too. `DefaultSiteDataTypes` (`cache`, `cookies`,
`storage`) includes `cookies`, so taking the library's own default silently
makes this choice without anyone deciding it.

usher has no stated assumption either way about its own deployment's domain
topology — REQUIREMENTS and the ADRs so far say nothing about whether it
runs on a dedicated subdomain or alongside other applications under the same
registrable domain, and a general-purpose AS (this project's own framing,
REQUIREMENTS §1) cannot assume it never will.

## Decision
`/logout` calls `secureheaders.ClearSiteData(secureheaders.SiteDataCache,
secureheaders.SiteDataStorage)` — explicitly naming the two directives it
wants, never the bare `ClearSiteData()` call that would silently pull in
`SiteDataCookies` through `DefaultSiteDataTypes`.

This costs nothing against RS-31's own guarantee: usher's session cookie is
`__Host-` prefixed (RS-31), so the browser already refuses to let any other
origin under the same registrable domain read or overwrite it, and
`/logout`'s own handler clears it directly with `ExpiredSessionCookie` (a
`Set-Cookie` with `MaxAge=-1`) regardless of what `Clear-Site-Data` says.
Omitting `SiteDataCookies` only means usher's logout does not *also* reach
into cookies other applications on the same registrable domain set for
themselves — it has no effect on usher's own cookie at all.

## The alternative that was rejected
**Sending the library's default (`cache`, `cookies`, `storage`).** Simpler —
one call with no arguments, matching `moat`'s own suggested default.
Rejected because the one thing `moat/secureheaders`'s own documentation
singles out as "worth checking before deploying" is exactly the scenario a
general-purpose AS cannot rule out: a registrable domain that hosts more
than this one application. Taking the default would make that call for
every future deployment without ever stating it, which is the wrong
direction for a decision the library itself flags as consequential.

## Consequences
- A deployment that *does* want cross-application logout on its own
  registrable domain does not get it from usher's own `/logout` — that
  would need its own, separately-decided mechanism (a shared logout
  endpoint, a federation protocol), not a side effect of this header.
- `cache` and `storage` still clear whatever the browser holds for usher's
  own origin specifically — the authenticated page cache and any
  origin-scoped storage, neither of which is reachable from another
  origin's logout regardless of this choice.

## Reopening criterion
Reopen if a concrete deployment needs same-registrable-domain,
cross-application logout from usher's own `/logout` — at that point, decide
and document the intended blast radius explicitly for that deployment,
rather than reaching for the library's default.
