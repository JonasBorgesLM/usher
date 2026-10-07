// router.go builds the chi.Mux ADR-0006 and REQUIREMENTS §7.2 describe.
// cmd/usher is the one binary that wires everything below it (ADR-0001), and
// a router that imports both internal/oauth and internal/proxy belongs here
// rather than under either — the one place both are allowed to meet.
//
// Every REQUIREMENTS §7.2 route group is registered here now, the last
// being /api/** (#104). newRouter and routeGroup.wrap (chain.go) are the
// reusable infrastructure each phase registered through as it landed;
// growing the router further is adding a line to newRouter and an entry
// to routeGroups, not building a new mechanism.
package main

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/JonasBorgesLM/bastion"
	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/secureheaders"
	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/keys"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/internal/proxy"
	"github.com/JonasBorgesLM/usher/internal/session"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

//go:embed templates/login.html.tmpl templates/logged_in.html.tmpl templates/authorize_error.html.tmpl templates/consent.html.tmpl templates/consent_error.html.tmpl templates/logout.html.tmpl templates/logged_out.html.tmpl
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

	// Families is /token's refresh_token grant (#36, #37): the same
	// FamilyStore the authorization_code grant creates a family through
	// when the client's grant_types include refresh_token (RF-02 Flow 2
	// steps 6-7), and that the refresh_token grant itself rotates
	// (RF-04 Flow 3). RefreshIdleTTL and RefreshAbsoluteTTL are RF-12's
	// own pair for it.
	Families           oauth.FamilyStore
	RefreshIdleTTL     time.Duration
	RefreshAbsoluteTTL time.Duration

	// Denylist is /revoke's own write side (#38, ADR-0014): the gateway's
	// own read side (proxy.NewHandler) is M6, but the store it reads from
	// is the same one /revoke writes to, so it is constructed here, not
	// deferred alongside the gateway itself.
	Denylist proxy.Denylist

	// GatewayUpstream and GatewayAudience are REQUIREMENTS §7.2's
	// "/api/**" row (#104): where the one proxied route forwards to, and
	// the audience pkg/tokenvalidator checks a bearer token against
	// before it does (RS-19). GatewayUpstream == nil means no gateway
	// route is mounted at all -- this repository's own test suite
	// leaves both unset, the same "absent by default" shape Emitter
	// already has.
	GatewayUpstream *url.URL
	GatewayAudience string

	// ConsumerJWKSCacheTTL is /.well-known/jwks.json's own Cache-Control
	// max-age (#33) -- the same duration RS-09's retirement formula was
	// already built against (keys.Load's own consumerJWKSCacheTTL
	// parameter), kept here too so the HTTP response's caching promise
	// and the key-retirement guarantee behind it cannot drift apart.
	ConsumerJWKSCacheTTL time.Duration

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
	"/login":                            browserForms,
	"/consent":                          browserForms,
	"/logout":                           browserForms,
	"/healthz":                          operational,
	"/readyz":                           operational,
	"/authorize":                        authorizeGroup,
	"/token":                            tokenGroup,
	"/revoke":                           tokenGroup,
	"/introspect":                       tokenGroup,
	"/userinfo":                         userinfoGroup,
	"/.well-known/jwks.json":            jwksGroup,
	"/.well-known/openid-configuration": jwksGroup,
	"/api/*":                            gatewayGroup, // #104; chi.Walk's own pattern for Mount("/api", ...)
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
	logoutTmpl := template.Must(template.ParseFS(templateFS, "templates/logout.html.tmpl"))
	loggedOutTmpl := template.Must(template.ParseFS(templateFS, "templates/logged_out.html.tmpl"))

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
		issuer:       deps.Issuer,
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
		clients:            deps.Clients,
		codes:              deps.Codes,
		families:           deps.Families,
		emitter:            deps.Emitter,
		keyset:             deps.Keyset,
		issuer:             deps.Issuer,
		accessTokenTTL:     deps.AccessTokenTTL,
		refreshIdleTTL:     deps.RefreshIdleTTL,
		refreshAbsoluteTTL: deps.RefreshAbsoluteTTL,
		now:                deps.Now,
		logger:             deps.Logger,
	}

	jwks := &jwksHandler{
		keyset:           deps.Keyset,
		consumerCacheTTL: deps.ConsumerJWKSCacheTTL,
		now:              deps.Now,
		logger:           deps.Logger,
	}

	discovery := &discoveryHandler{
		issuer: deps.Issuer,
		logger: deps.Logger,
	}

	logout := &logoutHandler{
		sessions:      deps.Sessions,
		logoutTmpl:    logoutTmpl,
		loggedOutTmpl: loggedOutTmpl,
		logger:        deps.Logger,
	}

	// bearerValidator checks an access token's signature and claim set
	// (RS-07) the same way for both of this binary's own bearer-token
	// callers, /revoke (#38) and /userinfo (#45): built over the same
	// keyset /token signs with (deps.Keyset.AsKeySource()), the same two
	// algorithms RS-06's allow-list permits. Each caller still picks its
	// own method — ValidateForRevocation for /revoke (no single
	// audience to require, RFC 7009 §2.1's own reasoning), AccessToken
	// for /userinfo (RS-08's userinfo audience) — the two were already
	// methods on the same *Validator before #45 gave this a second
	// caller to share with. New only fails on an empty allow-list, a
	// literal two elements long here, so a non-nil err is a programming
	// mistake in this call, not a runtime condition — template.Must's
	// own reasoning a few lines above, applied to this construction
	// instead.
	bearerValidator, err := tokenvalidator.New(
		deps.Keyset.AsKeySource(),
		[]tokenvalidator.Algorithm{tokenvalidator.RS256, tokenvalidator.ES256},
		tokenvalidator.WithIssuer(deps.Issuer),
		tokenvalidator.WithClock(deps.Now),
	)
	if err != nil {
		panic("router: build the shared bearer-token tokenvalidator.Validator: " + err.Error())
	}

	revoke := &revokeHandler{
		clients:   deps.Clients,
		families:  deps.Families,
		validator: bearerValidator,
		denylist:  deps.Denylist,
		emitter:   deps.Emitter,
		now:       deps.Now,
		logger:    deps.Logger,
	}

	introspect := &introspectHandler{
		clients:   deps.Clients,
		families:  deps.Families,
		validator: bearerValidator,
		issuer:    deps.Issuer,
		now:       deps.Now,
		logger:    deps.Logger,
	}

	userinfo := &userinfoHandler{
		validator: bearerValidator,
		audience:  userinfoAudience(deps.Issuer),
		logger:    deps.Logger,
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

	// /logout carries no rate limiter: unlike /login, nothing here cites
	// an RS-/RF- id asking for one, the same reasoning tokenGroup's own
	// comment gives for /token. clearSiteData (RS-27, ADR-0021) wraps
	// only the POST handler itself -- the action that actually logs out,
	// not the GET confirmation form -- so it fires exactly once, on the
	// response that does the logging out.
	clearSiteData := secureheaders.ClearSiteData(secureheaders.SiteDataCache, secureheaders.SiteDataStorage)
	r.Method(http.MethodGet, "/logout",
		browserForms.wrap(nil, deps.CSRFProtector, http.HandlerFunc(logout.get)))
	r.Method(http.MethodPost, "/logout",
		browserForms.wrap(nil, deps.CSRFProtector, clearSiteData(http.HandlerFunc(logout.post))))

	r.Method(http.MethodPost, "/token",
		tokenGroup.wrap(nil, nil, token))

	r.Method(http.MethodPost, "/revoke",
		tokenGroup.wrap(nil, nil, revoke))

	r.Method(http.MethodPost, "/introspect",
		tokenGroup.wrap(nil, nil, introspect))

	r.Method(http.MethodGet, "/userinfo",
		userinfoGroup.wrap(nil, nil, userinfo))

	r.Method(http.MethodGet, "/.well-known/jwks.json",
		jwksGroup.wrap(nil, nil, jwks))

	r.Method(http.MethodGet, "/.well-known/openid-configuration",
		jwksGroup.wrap(nil, nil, discovery))

	// #104: the one proxied route REQUIREMENTS §7.2 calls /api/**.
	// Mounted only when GatewayUpstream is set -- this repository's own
	// test suite, and any future deployment with nothing to proxy to,
	// get a router with no gateway at all, the same "absent by default"
	// shape Emitter already has. http.StripPrefix hands
	// proxy.NewHandler the upstream's own path shape (resource-server
	// defines "/widgets", never "/api/widgets" -- the prefix is this
	// gateway's own convention, not the upstream's concern).
	if deps.GatewayUpstream != nil {
		breaker, err := bastion.New("resource-server")
		if err != nil {
			panic("router: build the gateway's bastion.Breaker: " + err.Error())
		}
		gatewayHandler := proxy.NewHandler(
			proxy.Route{
				PathPrefix: "/api",
				Upstream:   deps.GatewayUpstream,
				Audience:   deps.GatewayAudience,
				Breaker:    breaker,
			},
			bearerValidator,
			deps.Denylist,
			deps.Logger,
		)
		r.Mount("/api", gatewayGroup.wrap(nil, nil, http.StripPrefix("/api", gatewayHandler)))
	}

	return r
}
