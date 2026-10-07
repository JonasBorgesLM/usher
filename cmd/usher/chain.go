// This file composes REQUIREMENTS §7.2's middleware chains in the fixed
// order ADR-0006 decided: secureheaders → ratelimit → validate.MaxBodyBytes
// → [csrf] → [auth] → [rbac] → handler. Headers outermost so that 401, 403
// and 429 responses carry them too; the body limit precedes CSRF because
// CSRF parses form-encoded bodies (moat/csrf's own Middleware doc says the
// same thing).
//
// secureheaders itself is wired once, globally, in newRouter rather than
// per group: every route group in REQUIREMENTS §7.2's table carries it with
// no group-dependent variation, so one instance covering the whole router is
// the fixed order's outermost layer without duplicating it per group.
package main

import (
	"net/http"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/secureheaders"
	"github.com/JonasBorgesLM/moat/validate"
)

// maxFormBodyBytes bounds a browser form POST (/login, /consent):
// comfortably above any real identifier, password and CSRF token together,
// far below anything useful as a resource-exhaustion lever.
const maxFormBodyBytes = 16 * 1024

// routeGroup is one row of REQUIREMENTS §7.2's table: which of the fixed
// chain's optional layers a group of routes carries. Every route the router
// registers names exactly one of these — see routeGroups in router.go — so
// that "what runs on this route" has one place to look up, and the property
// tests in router_test.go check every registered route against it, not
// against a hand-written list of routes.
type routeGroup struct {
	name string

	// csrf is REQUIREMENTS §7.2's "csrf" column: the browser-form routes
	// only (RS-12a). auth and rbac are the table's other two optional
	// layers; neither group registered in M1 uses them, so they are not
	// modeled yet — added when a group that needs one is (client auth on
	// /token, bearer+RBAC on /api/**).
	csrf bool

	// noStore is RS-26: Cache-Control: no-store on credential responses.
	noStore bool
}

// browserForms is REQUIREMENTS §7.2's "/login, /consent (POST)" row: CSRF
// required, no-store, strict two-axis rate limiting. The IP axis is the
// limiter composed here; the account axis is Authenticator's own, enforced
// inside the handler once an identifier is known (RS-22 keeps the two
// separate on purpose — see internal/identity/authenticator.go).
var browserForms = routeGroup{name: "browser-forms", csrf: true, noStore: true}

// operational is /healthz and /readyz: not in REQUIREMENTS §7.2's table at
// all (that table is the OAuth/OIDC protocol surface), no CSRF, no-store
// does not apply to a status response the way RS-26 means it, and —
// registered with a nil limiter (see wrap) — no rate limit, since an
// orchestrator polling every few seconds is the expected caller, not an
// attacker to throttle.
var operational = routeGroup{name: "operational", csrf: false, noStore: false}

// authorizeGroup is REQUIREMENTS §7.2's "/authorize" row: no CSRF (the
// request carries no form the attacker-controlled double-submit model
// applies to; RS-28's own ordering, not CSRF, is what keeps this route
// safe), no-store does not apply (no credential in the response), and a
// rate limit of its own — "moderate," distinct from /login's strict
// two-axis one, passed at registration rather than baked into the group.
var authorizeGroup = routeGroup{name: "authorize", csrf: false, noStore: false}

// tokenGroup is REQUIREMENTS §7.2's "/token, /revoke, /introspect" row, the
// slice of it /token itself needs: no CSRF (the request carries no
// cookie-based credential a double-submit model applies to — client
// authentication is the request's own body/header, checked inside the
// handler, not a middleware layer), no-store (RS-26 — a token response is
// exactly RS-26's "credential response"). The table's own "strict, weighted
// AllowN" rate limit (RF-07/RS-22) is deliberately not wired here: neither
// id is among #30's cited requirements, and wiring a limiter ahead of its
// own issue would invent the weighting scheme this group's row only names,
// not design — passing a nil limiter at registration, the same documented
// choice the operational group already makes for its own reason, defers it
// rather than hiding it.
var tokenGroup = routeGroup{name: "token", csrf: false, noStore: true}

// userinfoGroup is REQUIREMENTS §7.2's "/userinfo" row: no CSRF (bearer
// auth, not a cookie a double-submit model applies to), no-store (RS-26
// — RS-08's claims about the caller's identity are exactly the kind of
// response RS-26 means). Bearer authentication and the userinfo-audience
// check (RS-08) are inside userinfoHandler itself, the same choice
// tokenGroup's own comment already explains for /token's client auth and
// /revoke's token verification — not a new middleware layer. The table's
// "per token" rate limit is left unwired for the same reason tokenGroup
// leaves its own unwired: no RS-/RF- id for it is cited by this group's
// issue (#45 cites only RS-08, RS-26).
var userinfoGroup = routeGroup{name: "userinfo", csrf: false, noStore: true}

// jwksGroup is REQUIREMENTS §7.2's "/.well-known/*, JWKS" row: no CSRF, no
// auth, and -- deliberately the opposite of every credential route above --
// no-store does not apply. A public key set is not a credential; the whole
// point of #33's own Cache-Control wiring is that this response is cacheable,
// which RS-26's no-store would directly contradict. The table's "permissive,
// cached" rate limit is left unwired for the same reason tokenGroup's own
// comment already gives for /token: no RS-/RF- id for it is cited by this
// issue, and a cacheable response needs a rate limiter least of all the
// routes in this table.
var jwksGroup = routeGroup{name: "jwks", csrf: false, noStore: false}

// gatewayGroup is REQUIREMENTS §7.2's "/api/**" row: no CSRF (bearer auth,
// not a cookie a double-submit model applies to), and no-store is
// "upstream's choice" — the gateway must not force a Cache-Control the
// proxied response did not itself carry, so this group leaves noStore
// false the same way jwksGroup does for its own, different reason.
// Bearer authentication, the per-route audience check (RS-19), the
// gateway-local denylist (RF-06) and RF-05's own scope ∩ role check are
// all internal/proxy.NewHandler's own job, not a middleware layer here —
// the same choice tokenGroup's and userinfoGroup's comments already
// explain for client auth and bearer auth respectively. The table's own
// "per token/account" rate limit is still deliberately not wired: no
// RS-/RF- id here asks for a weighting scheme yet — the same "defer, do
// not invent" reasoning tokenGroup's own comment gives.
var gatewayGroup = routeGroup{name: "gateway", csrf: false, noStore: false}

// wrap composes h under g's chain, around limiter's IP axis and protector's
// CSRF check — ratelimit, then validate.MaxBodyBytes, then csrf if the group
// carries it, then no-store if the group carries it, innermost to outermost
// in that order so the fixed order reads top-to-bottom as secureheaders
// (applied by the caller) → ratelimit → MaxBodyBytes → [csrf] → handler.
//
// A group with csrf=true called with a nil protector panics rather than
// silently serving the route unprotected — the same reasoning
// moat/csrf.Token itself gives for returning a bool instead of a bare
// string: a wiring mistake here must be loud, not a quietly open CSRF hole.
//
// A nil limiter means the group carries no rate limiting at all, rather
// than panicking: unlike CSRF, "no limiter" is a deliberate, valid choice
// for a route an orchestrator polls every few seconds (operational, below)
// and for which a limit could produce a false negative on a tight poll
// interval — a wiring mistake here is "forgot the limiter," not "forgot
// that this route needs one."
func (g routeGroup) wrap(limiter *ratelimit.Limiter, protector *csrf.Protector, h http.Handler) http.Handler {
	if g.csrf {
		if protector == nil {
			panic("router: route group " + g.name + " requires CSRF but no protector was supplied")
		}
		h = protector.Middleware(h)
	}
	h = validate.MaxBodyBytes(maxFormBodyBytes)(h)
	if limiter != nil {
		h = limiter.Middleware(h)
	}
	if g.noStore {
		h = secureheaders.NoStore(h)
	}
	return h
}
