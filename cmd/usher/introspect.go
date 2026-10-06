// POST /introspect (RFC 7662, RS-25, RS-26, #50): a client asking whether
// a token it holds is still good. Shares /revoke's own dual-check shape
// exactly -- authenticate the client, try the presented value as an
// access token first (tokenvalidator.ValidateForRevocation's signature
// check tells the two token kinds apart deterministically), fall back to
// a refresh-token lookup on failure -- because the two endpoints answer
// the same underlying question about the same two token kinds, just with
// a different response shape on success.
//
// RFC 7662 §2.2's only required field is active. Every other cause --
// not found, expired, revoked, malformed, or genuinely active but issued
// to a different client -- collapses to the identical {"active":false}
// body (RS-25's ambiguity principle, the same one /token's invalid_grant
// and /revoke's own always-200 already apply, extended here so a caller
// cannot learn why a token is inactive by probing this endpoint with
// values it does not itself hold). Only unauthenticated callers and a
// missing "token" parameter are reported differently, as RFC 7662 itself
// requires.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

type introspectHandler struct {
	clients   []identity.Client
	families  oauth.FamilyStore
	validator *tokenvalidator.Validator
	issuer    string
	now       func() time.Time
	logger    *slog.Logger
}

// introspectBody is RFC 7662 §2.2's response, narrowed to the fields
// this project can answer truthfully. Active has no omitempty: it must
// be present, and false, on every inactive response -- the one field
// RFC 7662 requires unconditionally. Every other field's zero value is
// also its absence, so an inactive response built as the zero
// introspectBody{} serializes to exactly {"active":false}, never a
// hand-written literal that could drift from this type.
type introspectBody struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	JTI       string   `json:"jti,omitempty"`
}

func (h *introspectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	token := r.PostForm.Get("token")
	if token == "" {
		writeOAuthError(w, h.logger, http.StatusBadRequest, "invalid_request")
		return
	}

	client, errCode := authenticateClient(h.clients, r)
	if errCode != "" {
		if errCode == "invalid_client" {
			w.Header().Set("WWW-Authenticate", `Basic realm="usher"`)
			writeOAuthError(w, h.logger, http.StatusUnauthorized, errCode)
			return
		}
		writeOAuthError(w, h.logger, http.StatusBadRequest, errCode)
		return
	}

	if claims, err := h.validator.ValidateForRevocation(r.Context(), token); err == nil {
		h.introspectAccessToken(w, r, client, claims)
		return
	}
	h.introspectRefreshToken(w, r, client, token)
}

// introspectAccessToken reports on a cryptographically genuine access
// token. claims already carries the full RS-07 claim set
// (ValidateForRevocation); the only question left is RFC 7662's own
// binding check -- does this token belong to the caller -- plus the
// same clock-skew edge case revoke.go's own ttl<=0 branch documents: a
// token ValidateForRevocation accepted within its skew tolerance can
// still be past its own exp by this handler's stricter, skew-free
// comparison, and reporting that as active would contradict the exp it
// is about to hand back in the same response.
func (h *introspectHandler) introspectAccessToken(w http.ResponseWriter, r *http.Request, client identity.Client, claims tokenvalidator.Claims) {
	if claims.ClientID != client.ID {
		h.writeInactive(w, r)
		return
	}
	if !h.now().Before(claims.ExpiresAt) {
		h.writeInactive(w, r)
		return
	}
	h.writeJSON(w, r, introspectBody{
		Active:    true,
		Scope:     strings.Join(claims.Scope, " "),
		ClientID:  claims.ClientID,
		TokenType: "Bearer",
		Subject:   claims.Subject,
		Issuer:    h.issuer,
		Audience:  claims.Audience,
		ExpiresAt: claims.ExpiresAt.Unix(),
		IssuedAt:  claims.IssuedAt.Unix(),
		JTI:       claims.JTI,
	})
}

// introspectRefreshToken reports on the token as an opaque refresh
// value when it did not verify as a JWT at all. Lookup's own semantics
// already fold "never existed" and "past its own idle/absolute
// lifetime" into ErrRefreshTokenNotFound (internal/oauth's own doc
// comment on Lookup); RevokedAt and ConsumedAt are not, so both are
// checked here explicitly -- a revoked family, or this exact token
// value having already been rotated away, must not report active.
func (h *introspectHandler) introspectRefreshToken(w http.ResponseWriter, r *http.Request, client identity.Client, raw string) {
	hash := sha256.Sum256([]byte(raw))
	fam, tok, err := h.families.Lookup(r.Context(), hash)
	if err != nil {
		if errors.Is(err, oauth.ErrRefreshTokenNotFound) {
			h.writeInactive(w, r)
			return
		}
		h.logger.ErrorContext(r.Context(), "introspect: look up refresh token", "error", err)
		writeOAuthError(w, h.logger, http.StatusInternalServerError, "server_error")
		return
	}

	// RFC 7662's own binding check, the same one revoke.go's
	// revokeRefreshToken already applies: a family issued to a
	// different client is treated exactly like one that does not exist,
	// so a client cannot use this endpoint to confirm another client's
	// refresh token is live.
	if fam.ClientID != client.ID {
		h.writeInactive(w, r)
		return
	}
	if fam.RevokedAt != nil || tok.ConsumedAt != nil {
		h.writeInactive(w, r)
		return
	}

	h.writeJSON(w, r, introspectBody{
		Active:    true,
		Scope:     strings.Join(fam.Scope, " "),
		ClientID:  fam.ClientID,
		Subject:   fam.Subject,
		Issuer:    h.issuer,
		ExpiresAt: fam.ExpiresAt.Unix(),
	})
}

func (h *introspectHandler) writeInactive(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, r, introspectBody{})
}

func (h *introspectHandler) writeJSON(w http.ResponseWriter, r *http.Request, body introspectBody) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger.ErrorContext(r.Context(), "introspect: encode response", "error", err)
	}
}
