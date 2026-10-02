// POST /revoke (RFC 7009): a client's own revocation of its access or
// refresh token. Revoking a refresh token revokes its whole family
// (RS-11's family concept, reused here for RF-06); revoking an access
// token puts its jti on the gateway's Redis denylist with a TTL equal to
// its own remaining lifetime (ADR-0014) — the gateway is the only
// consumer of that denylist (RS-18), so revocation here is gateway-local,
// exactly as RF-06 states and never claims more than.
//
// Every response is 200 regardless of whether token was ever found,
// valid, belonged to a different client, or was already revoked (RFC
// 7009 §2.2) — the same ambiguity RS-25 already asks of invalid_grant,
// extended here so a client probing values at this endpoint learns
// nothing from the response shape. Only client authentication failure
// and a missing "token" parameter are reported differently, as the same
// RFC requires.
//
// Which of the two token types was presented is never asked of the
// caller (no token_type_hint handling): ValidateForRevocation's own
// signature check already tells the two apart deterministically — a
// genuine access token verifies; a refresh token (an opaque,
// high-entropy string, never JWS-shaped) cannot — so guessing from a
// client-supplied hint first would only add a second, unnecessary path
// to the same answer.
package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/internal/proxy"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

type revokeHandler struct {
	clients   []identity.Client
	families  oauth.FamilyStore
	validator *tokenvalidator.Validator
	denylist  proxy.Denylist
	emitter   audit.Emitter // RF-09; nil emits nothing
	now       func() time.Time
	logger    *slog.Logger
}

func (h *revokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		h.revokeAccessToken(w, r, client, claims)
		return
	}
	h.revokeRefreshToken(w, r, client, token)
}

// revokeAccessToken is RFC 7009 applied to an access token: ADR-0014's
// own write side. claims already carries a verified signature and the
// full RS-07 claim set (tokenvalidator.ValidateForRevocation) — only
// RFC 7009 §2.1's own binding check (does this token belong to the
// caller) is this function's job, not the token's cryptographic
// authenticity.
func (h *revokeHandler) revokeAccessToken(w http.ResponseWriter, r *http.Request, client identity.Client, claims tokenvalidator.Claims) {
	if claims.ClientID != client.ID {
		h.writeSuccess(w)
		return
	}

	ttl := claims.ExpiresAt.Sub(h.now())
	if ttl > 0 {
		if err := h.denylist.Add(r.Context(), claims.JTI, ttl); err != nil {
			h.logger.ErrorContext(r.Context(), "revoke: add to denylist", "error", err)
			writeOAuthError(w, h.logger, http.StatusInternalServerError, "server_error")
			return
		}
		h.emitRevocation(r.Context(), client.ID, claims.Subject)
	}
	// ttl <= 0: the token had already expired on its own; ADR-0014's
	// bound is the token's own exp either way, so there is nothing left
	// for the denylist to shorten. Treated as success, same as any other
	// already-moot revocation.
	h.writeSuccess(w)
}

// revokeRefreshToken is RFC 7009 applied to a refresh token: RF-06's
// "revoking a refresh token revokes its family," reusing
// oauth.FamilyStore.Revoke (#36) rather than a second revocation
// mechanism.
func (h *revokeHandler) revokeRefreshToken(w http.ResponseWriter, r *http.Request, client identity.Client, raw string) {
	hash := sha256.Sum256([]byte(raw))
	fam, _, err := h.families.Lookup(r.Context(), hash)
	if err != nil {
		if errors.Is(err, oauth.ErrRefreshTokenNotFound) {
			h.writeSuccess(w) // RFC 7009 §2.2: unknown token is still success
			return
		}
		h.logger.ErrorContext(r.Context(), "revoke: look up refresh token", "error", err)
		writeOAuthError(w, h.logger, http.StatusInternalServerError, "server_error")
		return
	}

	// RFC 7009 §2.1: the server must verify the token belongs to the
	// authenticated client -- a family issued to a different client is
	// treated exactly like one that does not exist, so a client cannot
	// use this endpoint to even confirm another client's refresh token
	// is currently live.
	if fam.ClientID != client.ID {
		h.writeSuccess(w)
		return
	}

	alreadyRevoked := fam.RevokedAt != nil
	if err := h.families.Revoke(r.Context(), fam.ID, "revoked_by_client"); err != nil {
		h.logger.ErrorContext(r.Context(), "revoke: revoke family", "error", err)
		writeOAuthError(w, h.logger, http.StatusInternalServerError, "server_error")
		return
	}
	if !alreadyRevoked {
		h.emitRevocation(r.Context(), client.ID, fam.Subject)
	}
	h.writeSuccess(w)
}

// writeSuccess is RFC 7009 §2.2: 200, empty body, regardless of which
// branch above reached it. Cache-Control: no-store is tokenGroup's own
// (chain.go), applied around this handler, not written here.
func (h *revokeHandler) writeSuccess(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
}

func (h *revokeHandler) emitRevocation(ctx context.Context, clientID, subject string) {
	if h.emitter == nil {
		return
	}
	h.emitter.Emit(ctx, audit.Event{
		Type:     audit.EventRevocation,
		Outcome:  audit.OutcomeSuccess,
		Subject:  subject,
		ClientID: clientID,
		At:       h.now(),
	})
}
