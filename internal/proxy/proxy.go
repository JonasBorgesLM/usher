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
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/JonasBorgesLM/bastion"
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

// Route is one proxied route's static configuration. Audience is required —
// a Route without one is a startup error (RS-19, RNF-05), enforced by
// internal/config's loader, not by this type.
type Route struct {
	PathPrefix string
	Upstream   *url.URL
	Audience   string
	Breaker    *bastion.Breaker // RI-02, ADR-0016: one named breaker per upstream — wired in #42; this issue (#40) does not call it yet
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
func NewHandler(route Route, validator *tokenvalidator.Validator, denylist Denylist, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = route.Upstream.Scheme
			req.URL.Host = route.Upstream.Host
			req.Host = route.Upstream.Host
		},
		Transport: newUpstreamTransport(),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.ErrorContext(r.Context(), "proxy: upstream error", "error", err)
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
		r.Header.Set("X-Auth-Subject", claims.Subject)
		r.Header.Set("X-Auth-Client", claims.ClientID)
		r.Header.Set("X-Auth-Scope", strings.Join(claims.Scope, " "))

		rp.ServeHTTP(w, r)
	})
}
