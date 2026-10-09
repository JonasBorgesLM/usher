// Package proxy is the gateway half of usher: the reverse proxy, identity
// header handling, and the gateway-local revocation check. It imports
// pkg/tokenvalidator (never internal/keys directly — a Handler is handed an
// already-constructed *tokenvalidator.Validator) and bastion (RI-02,
// ADR-0016). It must never import internal/oauth or internal/oidc
// (ADR-0001): the whole reason that boundary holds by construction is that
// nothing in this package has a way to reach an oauth.Code or oauth.Family
// type — tokens are opaque strings here, validated, not issued.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/JonasBorgesLM/bastion"
	"github.com/JonasBorgesLM/usher/internal/rbac"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

// Denylist is the gateway-local revocation check (RF-06, ADR-0014). Its
// only consumer is this package; the demo resource server never sees it
// (RS-18) because cmd/resource-server does not import internal/ at all.
// Implemented in internal/store/redis.
type Denylist interface {
	// Contains reports whether jti is revoked. A non-nil error must be
	// treated as revoked by the caller (RNF-04: infrastructure failure
	// denies) — "unknown" and "revoked" collapse to the same response.
	Contains(ctx context.Context, jti string) (bool, error)

	Add(ctx context.Context, jti string, ttl time.Duration) error
}

// RoleLookup resolves the authenticated subject's own role for RF-05's
// scope ∩ role intersection — the [rbac] half of REQUIREMENTS §7.2's
// /api/** row, wired in alongside [auth] rather than as a separate
// middleware layer, since there is no seam between the two inside this
// handler for one to sit in (NewHandler validates the token, checks the
// denylist, injects headers and proxies in one function, not a chain).
// internal/identity.User.Role is the real backing field; this interface
// exists so this package never imports internal/identity directly — the
// same "tokens are opaque strings here" boundary this file's own package
// doc already promises extends to "and so are subjects."
type RoleLookup interface {
	// RoleOf returns subject's role, or a non-nil error if it cannot be
	// resolved (no such user, or a lookup failure) — the caller treats
	// either the same way NewHandler already treats a denylist error
	// (RNF-04: infrastructure or data failure denies, never allows).
	RoleOf(ctx context.Context, subject string) (string, error)
}

// Route is one proxied route's static configuration. Audience is required
// — ValidateRoute, called by NewHandler itself (#41), refuses a Route
// without one rather than silently serving requests for it. Permission is
// required whenever NewHandler is given a non-nil *rbac.Authorizer (RF-05)
// — checked by NewHandler itself, not ValidateRoute, since "required" here
// is conditional on a parameter ValidateRoute never sees.
type Route struct {
	PathPrefix string
	Upstream   *url.URL
	Audience   string
	Permission string           // RF-05: checked against scope ∩ role when an Authorizer is given to NewHandler
	Breaker    *bastion.Breaker // RI-02, ADR-0016: one named breaker per upstream — wired in #42; this issue does not call it yet
}

// ValidateRoute is RS-19/RNF-05: a proxied route with no Audience must
// refuse to start, not serve requests with the audience check silently
// skipped. tokenvalidator.Validator.ValidateAccessToken treats an empty
// wantAudience as "no audience required" — an audience-less Route would
// make NewHandler accept a token issued for any resource server behind
// this gateway, defeating RS-19's whole point (a token for RS-A refused
// at RS-B's route) rather than merely weakening it.
func ValidateRoute(route Route) error {
	if route.Audience == "" {
		return fmt.Errorf("proxy: route %q has no audience (RS-19)", route.PathPrefix)
	}
	return nil
}

// identityHeaderPrefix is RI-04's own namespace. RS-17 requires removing
// every inbound header under it before this package injects its own — an
// allow-list of what survives from the client in this namespace (nothing,
// unconditionally), not a block-list naming the three specific headers
// below (a client sending a fourth, never-named one would otherwise sail
// through untouched).
const identityHeaderPrefix = "X-Auth-"

// stripIdentityHeaders deletes every inbound header under
// identityHeaderPrefix, before anything else in this package touches req
// — RS-17's own ordering ("before injecting its own"). Deleting map
// entries while ranging over the same map is explicitly safe in Go (the
// spec guarantees a deleted entry is not produced); req.Header's keys are
// already in canonical form (textproto canonicalizes while parsing the
// wire), so this needs no case-folding of its own.
func stripIdentityHeaders(req *http.Request) {
	for name := range req.Header {
		if strings.HasPrefix(name, identityHeaderPrefix) {
			req.Header.Del(name)
		}
	}
}

// bearerToken extracts the credential from an "Authorization: Bearer ..."
// header. ok is false for a missing header, a different scheme, or no
// token after the scheme.
func bearerToken(req *http.Request) (token string, ok bool) {
	return strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
}

// The upstream half of RS-21's explicit-timeouts requirement; the server
// half is cmd/usher/serve.go's newServer. net/http's own default for
// every one of these is "no timeout at all."
const (
	upstreamDialTimeout           = 5 * time.Second
	upstreamTLSHandshakeTimeout   = 5 * time.Second
	upstreamResponseHeaderTimeout = 10 * time.Second
	upstreamExpectContinueTimeout = 1 * time.Second
	upstreamIdleConnTimeout       = 90 * time.Second

	// maxUpstreamResponseBytes is RS-21's own response size limit: large
	// enough for any real resource-server response this project proxies,
	// far below what a misbehaving or malicious upstream streaming
	// indefinitely could use to exhaust the gateway's memory.
	maxUpstreamResponseBytes = 10 << 20 // 10 MiB
)

// upstreamDialer is a package-level var, not a literal inlined into
// newUpstreamTransport, so DialContext and its own Timeout stay the same
// value a test can read back directly.
var upstreamDialer = &net.Dialer{Timeout: upstreamDialTimeout}

// newUpstreamTransport builds RS-21's upstream client. Pulled out of
// NewHandler so a test can read every timeout back without constructing
// a whole Route, Validator and Denylist just to inspect them.
func newUpstreamTransport() *http.Transport {
	return &http.Transport{
		DialContext:           upstreamDialer.DialContext,
		TLSHandshakeTimeout:   upstreamTLSHandshakeTimeout,
		ResponseHeaderTimeout: upstreamResponseHeaderTimeout,
		ExpectContinueTimeout: upstreamExpectContinueTimeout,
		IdleConnTimeout:       upstreamIdleConnTimeout,
	}
}

// limitedBody caps how much of an upstream response NewHandler will ever
// copy to the client, while still closing the real underlying body —
// io.LimitReader alone is not an io.Closer, and httputil.ReverseProxy
// closes res.Body itself once it is done copying from it.
type limitedBody struct {
	io.Reader
	io.Closer
}

// gatewayErrorHandler is RS-20/T-17's own response: an upstream failure
// (dial refused, timeout, connection reset) must not leak the upstream's
// hostname, port or a stack trace to the client — this gateway's own
// caller, not the upstream's. err's own text (Go's transport errors embed
// the literal dial address, e.g. "dial tcp 10.0.0.5:8080: connect:
// connection refused") is deliberately never written to the response;
// logging it is the caller's own job (NewHandler's logger parameter),
// kept separate from what the client receives.
func gatewayErrorHandler(w http.ResponseWriter, _ *http.Request, _ error) {
	w.WriteHeader(http.StatusBadGateway)
}

// breakerRetryAfterSeconds is ADR-0016's own rule 1 half-answered: a
// static, conservative Retry-After, not one derived from the breaker's
// own configured WithOpenTimeout. bastion.Breaker exposes Counts (state,
// OpenedAt) but not the open-timeout duration itself, and Counts.OpenedAt
// is zero for StateHalfOpen's own rejection (ErrTooManyRequests) in any
// case — there is no value to compute an exact remaining wait from for
// that one. Per ADR-0016's own charge ("usher becomes bastion's first
// real integration and should report back what its API cost to use"),
// this gap is the finding: a real caller wanting a precise Retry-After
// needs bastion to expose the configured timeout, which it does not yet.
const breakerRetryAfterSeconds = 30

// breakerRoundTripper wraps an http.RoundTripper in one *bastion.Breaker
// (ADR-0016: "one named breaker per upstream, wrapping the outbound
// call"). httputil.ReverseProxy's own Transport.RoundTrip is the one
// outbound call per incoming request this package makes — wrapping it
// here, rather than rp.ServeHTTP itself, is what lets a rejection reach
// ReverseProxy's existing ErrorHandler path (#40) as an ordinary
// RoundTrip error, instead of needing a second, parallel error-handling
// mechanism: ReverseProxy.ServeHTTP has no return value for an error to
// come back through.
type breakerRoundTripper struct {
	breaker *bastion.Breaker
	next    http.RoundTripper
}

// RoundTrip implements http.RoundTripper, admitting through rt.breaker
// before ever calling rt.next.
//
// bastion classifies only the error an operation returns, and a 5xx answer
// is not a RoundTrip error — so an upstream that is up but failing would
// count as healthy forever. An unhealthy answer is therefore carried out
// of Execute as an error (so it counts against the threshold) and unwrapped
// back into the response here, so the client still receives the upstream's
// own answer while the circuit is closed (ADR-0016's amendment).
func (rt *breakerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := bastion.Execute(req.Context(), rt.breaker, func(ctx context.Context) (*http.Response, error) {
		resp, err := rt.next.RoundTrip(req)
		if err == nil && upstreamUnhealthy(resp.StatusCode) {
			return nil, &unhealthyUpstreamError{resp: resp}
		}
		return resp, err
	})
	if unhealthy, ok := errors.AsType[*unhealthyUpstreamError](err); ok {
		return unhealthy.resp, nil
	}
	return resp, err
}

// upstreamUnhealthy is ADR-0016's amendment: 502, 503 and 504 say the
// dependency itself is unwell. A 500 is excluded — it is usually one
// request's own bug, and opening the circuit for it would refuse every
// request because one endpoint is broken.
func upstreamUnhealthy(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

// unhealthyUpstreamError carries an unhealthy response through
// bastion.Execute; it never leaves breakerRoundTripper.
type unhealthyUpstreamError struct {
	resp *http.Response
}

func (e *unhealthyUpstreamError) Error() string {
	return "proxy: upstream answered " + e.resp.Status
}

// unauthorized is every auth-failure response this handler returns:
// missing bearer token, a token that fails ValidateAccessToken, or one
// found on the denylist. One body (none) for all three, the same
// RS-23/RS-25 "no internal detail" discipline this project's own
// protocol errors already apply, extended here so a caller cannot tell
// "expired" from "revoked" from "never valid" by response shape.
func unauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
}

// NewHandler builds the reverse proxy for one Route. It reaches tokens
// only through validator (pkg/tokenvalidator, constructed over
// keys.Keyset.AsKeySource — internal/keys, not internal/oauth) and
// denylist. This is the whole reason ADR-0001's boundary holds by
// construction: nothing here has a way to reach an oauth.Code or
// oauth.Family type.
//
// A nil logger discards — this package does not import cmd/usher, so it
// cannot reuse discardLogger there, but the contract is the same one
// every handler in that package already follows.
//
// roles and authorizer are RF-05's own pair: a nil authorizer means no
// RBAC check runs at all for this Route — the same "absent is a
// deliberate, valid choice" shape route.Breaker already has — but a
// non-nil authorizer with an empty route.Permission panics, the same
// "wiring mistake must be loud" reasoning ValidateRoute's own Audience
// check already follows.
//
// Panics if route fails ValidateRoute (RS-19, RNF-05) — the same
// "refuses to start" this package's own doc comment promises, applied
// here directly since nothing yet loads a Route from outside Go code
// for a startup-time error to attach to instead.
func NewHandler(route Route, validator *tokenvalidator.Validator, denylist Denylist, roles RoleLookup, authorizer *rbac.Authorizer, logger *slog.Logger) http.Handler {
	if err := ValidateRoute(route); err != nil {
		panic(err)
	}
	if authorizer != nil && route.Permission == "" {
		panic(fmt.Sprintf("proxy: route %q has an Authorizer but no Permission (RF-05)", route.PathPrefix))
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	var transport http.RoundTripper = newUpstreamTransport()
	if route.Breaker != nil {
		transport = &breakerRoundTripper{breaker: route.Breaker, next: transport}
	}

	rp := &httputil.ReverseProxy{
		// Rewrite, not Director (#137): ReverseProxy removes the hop-by-hop
		// headers a client names in Connection *after* Director runs, so a
		// client sending "Connection: X-Auth-Subject" could delete the
		// identity the gateway injected. Rewrite runs after that removal,
		// on pr.Out, so what is set here reaches the upstream.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = route.Upstream.Scheme
			pr.Out.URL.Host = route.Upstream.Host
			pr.Out.Host = route.Upstream.Host
			// pr.In holds only the gateway's own X-Auth-* values by now:
			// stripIdentityHeaders removed the client's before they were set.
			for name, values := range pr.In.Header {
				if strings.HasPrefix(name, identityHeaderPrefix) {
					pr.Out.Header[name] = values
				}
			}
			// Director mode appended the client's address to any existing
			// X-Forwarded-For; Rewrite mode drops the header instead. Keep the
			// old shape, which the resource server's realip (ADR-0010) reads.
			// SetXForwarded is not used: it would also add X-Forwarded-Host and
			// -Proto, which nothing downstream expects.
			if clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
				if prior := pr.In.Header.Values("X-Forwarded-For"); len(prior) > 0 {
					clientIP = strings.Join(prior, ", ") + ", " + clientIP
				}
				pr.Out.Header.Set("X-Forwarded-For", clientIP)
			}
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.ErrorContext(r.Context(), "proxy: upstream error", "error", err)
			// ADR-0016 rule 1: a breaker rejection is 503 + Retry-After,
			// never the bare 502 a genuine upstream failure gets --
			// "the circuit is open" is not the same fact as "the
			// upstream is down," and a caller retrying immediately
			// against a 502 would be doing exactly what the breaker
			// exists to stop.
			if errors.Is(err, bastion.ErrOpenState) || errors.Is(err, bastion.ErrTooManyRequests) {
				w.Header().Set("Retry-After", strconv.Itoa(breakerRetryAfterSeconds))
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			gatewayErrorHandler(w, r, err)
		},
		// RS-21's response-size half: res.Body is swapped for a reader
		// that stops at maxUpstreamResponseBytes, before ReverseProxy's
		// own copyResponse ever starts streaming it to the client.
		ModifyResponse: func(res *http.Response) error {
			res.Body = limitedBody{Reader: io.LimitReader(res.Body, maxUpstreamResponseBytes), Closer: res.Body}
			return nil
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RS-17: strip before validating or injecting anything else —
		// a spoofed header must not survive even as far as being read
		// by this handler's own logic below.
		stripIdentityHeaders(r)

		token, ok := bearerToken(r)
		if !ok {
			unauthorized(w)
			return
		}

		claims, err := validator.ValidateAccessToken(r.Context(), token, route.Audience)
		if err != nil {
			unauthorized(w)
			return
		}

		// RF-06/ADR-0014: the gateway-local revocation check. A denylist
		// error collapses to the same outcome as "revoked" (RNF-04:
		// infrastructure failure denies), never to "allowed."
		revoked, err := denylist.Contains(r.Context(), claims.JTI)
		if err != nil || revoked {
			unauthorized(w)
			return
		}

		// RI-04: inject only after every check above passed. These are
		// the only three headers in the identity namespace this
		// package ever sets, and stripIdentityHeaders already
		// guaranteed nothing else under that prefix survived from the
		// client by the time execution reaches here.
		serveProxied := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-Auth-Subject", claims.Subject)
			r.Header.Set("X-Auth-Client", claims.ClientID)
			r.Header.Set("X-Auth-Scope", strings.Join(claims.Scope, " "))
			rp.ServeHTTP(w, r)
		})

		if authorizer == nil {
			serveProxied.ServeHTTP(w, r)
			return
		}

		// RF-05: the [rbac] half of REQUIREMENTS §7.2's /api/** row,
		// built on internal/rbac's own intended seam
		// (WithScope/WithRole + RequirePermission, documented on that
		// package itself) rather than calling Authorizer.Allowed
		// directly — ADR-0006's own [auth] → [rbac] chain order, with
		// this handler playing [auth]'s part. A role-lookup failure
		// collapses to unauthorized() (RNF-04 again): the subject
		// itself could not be resolved, which is closer to "an invalid
		// credential" than to "a known identity without permission" —
		// RequirePermission's own 403 is reserved for that second case.
		role, err := roles.RoleOf(r.Context(), claims.Subject)
		if err != nil {
			unauthorized(w)
			return
		}
		ctx := rbac.WithRole(rbac.WithScope(r.Context(), claims.Scope), role)
		authorizer.RequirePermission(route.Permission)(serveProxied).ServeHTTP(w, r.WithContext(ctx))
	})
}
