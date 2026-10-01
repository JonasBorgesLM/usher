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
	"github.com/go-chi/chi/v5/middleware"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/secureheaders"
	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/keys"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/internal/session"
)

//go:embed templates/login.html.tmpl templates/logged_in.html.tmpl templates/authorize_error.html.tmpl templates/consent.html.tmpl templates/consent_error.html.tmpl
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

	// Clients and Issuer are /authorize's own (#26): the static registry
	// (#25) looked up by client_id, and RS-29's iss, carried on every
	// error redirect.
	Clients          []identity.Client
	AuthorizeLimiter *ratelimit.Limiter // REQUIREMENTS §7.2's "moderate" rate for /authorize
	Issuer           string
	ChallengeTTL     time.Duration

	// Consents is /consent's own (#28): RF-13's per-(subject, client) grant.
	Consents oauth.ConsentStore

	// Codes, Keyset and AccessTokenTTL are shared by /consent's code
	// issuance (RF-02 Flow 1 steps 10-11) and /token's consumption of it
	// (RF-02 Flow 2, #30): the same CodeStore on both sides, the signing
	// keyset /token signs with, and the access token's lifetime (RF-06's
	// gateway-local revocation bound).
	Codes          oauth.CodeStore
	Keyset         *keys.Keyset
	AuthCodeTTL    time.Duration
	AccessTokenTTL time.Duration

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
	"/login":     browserForms,
	"/consent":   browserForms,
	"/healthz":   operational,
	"/readyz":    operational,
	"/authorize": authorizeGroup,
	"/token":     tokenGroup,
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
	authorizeErrorTmpl := template.Must(template.ParseFS(templateFS, "templates/authorize_error.html.tmpl"))

	authorize := &authorizeHandler{
		clients:      deps.Clients,
		challenges:   deps.Challenges,
		issuer:       deps.Issuer,
		challengeTTL: deps.ChallengeTTL,
		now:          deps.Now,
		errorTmpl:    authorizeErrorTmpl,
		logger:       deps.Logger,
	}

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

	consentTmpl := template.Must(template.ParseFS(templateFS, "templates/consent.html.tmpl"))
	consentErrorTmpl := template.Must(template.ParseFS(templateFS, "templates/consent_error.html.tmpl"))

	consent := &consentHandler{
		clients:     deps.Clients,
		challenges:  deps.Challenges,
		consents:    deps.Consents,
		codes:       deps.Codes,
		protector:   deps.CSRFProtector,
		issuer:      deps.Issuer,
		codeTTL:     deps.AuthCodeTTL,
		now:         deps.Now,
		consentTmpl: consentTmpl,
		errorTmpl:   consentErrorTmpl,
		logger:      deps.Logger,
	}

	token := &tokenHandler{
		clients:        deps.Clients,
		codes:          deps.Codes,
		keyset:         deps.Keyset,
		issuer:         deps.Issuer,
		accessTokenTTL: deps.AccessTokenTTL,
		now:            deps.Now,
		logger:         deps.Logger,
	}

	r := chi.NewRouter()
	// RequestID first, so every layer after it — including a handler's own
	// error logging — can correlate by it (RNF-10; see log.go's
	// requestIDHandler, which is what actually reads this back out).
	r.Use(middleware.RequestID)
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

	r.Method(http.MethodGet, "/authorize",
		authorizeGroup.wrap(deps.AuthorizeLimiter, nil, authorize))

	r.Method(http.MethodGet, "/consent",
		browserForms.wrap(deps.LoginLimiter, deps.CSRFProtector, http.HandlerFunc(consent.get)))
	r.Method(http.MethodPost, "/consent",
		browserForms.wrap(deps.LoginLimiter, deps.CSRFProtector, http.HandlerFunc(consent.post)))

	r.Method(http.MethodPost, "/token",
		tokenGroup.wrap(nil, nil, token))

	return r
}
