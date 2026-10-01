// router.go builds the chi.Mux ADR-0006 and REQUIREMENTS §7.2 describe.
// cmd/usher is the one binary that wires everything below it (ADR-0001), and
// a router that imports both internal/oauth and internal/proxy belongs here
// rather than under either — the one place both are allowed to meet.
//
// Only "/login" is registered in M1: it is the one REQUIREMENTS §7.2 route
// group this phase can serve for real (the identity/session pieces #12-#20
// built). The other five groups' handlers do not exist until their own
// phase (REQUIREMENTS §11) — registering a stub for them now would invent
// auth/rbac middleware ahead of the design that is supposed to produce it.
// newRouter and routeGroup.wrap (chain.go) are the reusable infrastructure
// those phases register through; growing the router is adding a line to
// newRouter and an entry to routeGroups, not building a new mechanism.
package main

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/secureheaders"
	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/session"
)

//go:embed templates/login.html.tmpl templates/logged_in.html.tmpl
var templateFS embed.FS

// routerDeps is everything newRouter needs. Each field is an interface or a
// *moat type this binary already builds elsewhere (identity.Authenticator
// in internal/identity, session.SessionStore/ChallengeStore backed by Redis
// in internal/store/redis) — newRouter wires them into routes, and does not
// construct any of them itself, so a test can supply fakes the same way
// internal/session's own tests do.
type routerDeps struct {
	Authenticator *identity.Authenticator
	Sessions      session.SessionStore
	Challenges    session.ChallengeStore
	CSRFProtector *csrf.Protector
	LoginLimiter  *ratelimit.Limiter // REQUIREMENTS §7.2's IP axis for /login
	Emitter       audit.Emitter      // RF-09; nil emits nothing

	ReadinessChecks []ReadinessCheck // RNF-10's /readyz dependencies

	SessionIdleTTL     time.Duration
	SessionAbsoluteTTL time.Duration
	Now                func() time.Time // defaults to time.Now when nil

	Logger *slog.Logger // defaults to a discard logger when nil
}

// routeGroups maps every pattern newRouter registers to the REQUIREMENTS
// §7.2 group it belongs to. router_test.go's property tests read this same
// table — the one place "what group is this route in" is answered — rather
// than keeping a second, independently-maintained list; chi.Walk is what
// supplies the set of routes to check it against.
var routeGroups = map[string]routeGroup{
	"/login":   browserForms,
	"/healthz": operational,
	"/readyz":  operational,
}

func newRouter(deps routerDeps) *chi.Mux {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Logger == nil {
		deps.Logger = discardLogger()
	}

	loginTmpl := template.Must(template.ParseFS(templateFS, "templates/login.html.tmpl"))
	loggedInTmpl := template.Must(template.ParseFS(templateFS, "templates/logged_in.html.tmpl"))

	login := &loginHandler{
		auth:         deps.Authenticator,
		sessions:     deps.Sessions,
		challenges:   deps.Challenges,
		protector:    deps.CSRFProtector,
		emitter:      deps.Emitter,
		idleTTL:      deps.SessionIdleTTL,
		absoluteTTL:  deps.SessionAbsoluteTTL,
		now:          deps.Now,
		loginTmpl:    loginTmpl,
		loggedInTmpl: loggedInTmpl,
		logger:       deps.Logger,
	}

	r := chi.NewRouter()
	// secureheaders is the fixed order's outermost, universal layer (see
	// chain.go) — WithNonce enables RS-36's per-request script nonce for
	// login's template; a route group that never renders a script still
	// gets the header, which costs one CSPRNG call and nothing else.
	r.Use(secureheaders.Middleware(secureheaders.WithNonce()))

	r.Method(http.MethodGet, "/login",
		browserForms.wrap(deps.LoginLimiter, deps.CSRFProtector, http.HandlerFunc(login.get)))
	r.Method(http.MethodPost, "/login",
		browserForms.wrap(deps.LoginLimiter, deps.CSRFProtector, http.HandlerFunc(login.post)))

	r.Method(http.MethodGet, "/healthz",
		operational.wrap(nil, nil, http.HandlerFunc(healthzHandler)))
	r.Method(http.MethodGet, "/readyz",
		operational.wrap(nil, nil, &readinessHandler{checks: deps.ReadinessChecks, logger: deps.Logger}))

	return r
}
