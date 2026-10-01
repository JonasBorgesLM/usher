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
