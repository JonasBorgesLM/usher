// Package grant holds one Strategy per grant_type (§8's Strategy pattern),
// dispatched by the /token Facade. It imports internal/oauth (for
// TokenResponse) and internal/identity (for Client) — never
// internal/proxy.
package grant

import (
	"context"
	"net/http"

	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/oauth"
)

// Strategy is dispatched by the /token Facade on the request's grant_type.
type Strategy interface {
	// GrantType is the exact string this Strategy handles
	// ("authorization_code", "refresh_token", "client_credentials").
	GrantType() string

	// Issue validates the request against this grant's own rules and
	// returns tokens, or an RFC 6749 §5.2 error (RS-25) — never one that
	// leaks internal detail. client is already authenticated by the Facade
	// before Issue is called; a Strategy does not re-authenticate it.
	Issue(ctx context.Context, r *http.Request, client identity.Client) (oauth.TokenResponse, error)
}
