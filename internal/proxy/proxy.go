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
	"net/http"
	"net/url"
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
	Breaker    *bastion.Breaker // RI-02, ADR-0016: one named breaker per upstream
}

// NewHandler builds the reverse proxy for one Route. It reaches tokens only
// through validator and denylist — never through internal/oauth.
//
// Implemented in M6 (REQUIREMENTS §11).
func NewHandler(route Route, validator *tokenvalidator.Validator, denylist Denylist) http.Handler {
	panic("proxy: NewHandler not implemented (M6)")
}
