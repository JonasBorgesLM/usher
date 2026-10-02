// POST /token (docs/ARCHITECTURE.md §11-12): the authorization_code grant
// (M2) issuing an access token, and now the refresh_token grant (M4),
// bound to its own client and grant (RS-34, #37) via oauth.FamilyStore.Lookup
// and rotated through oauth.RotateRefreshToken (#36). A client whose
// grant_types include refresh_token also receives one from the
// authorization_code exchange (RF-02 Flow 2 steps 6-7) — the authorization
// code is tombstoned against the new family only then, so #29's own replay
// detection becomes reachable for real once a family exists to revoke.
// Client authentication (RS-16) is shared by both grants, done once before
// branching. Every error follows RFC 6749 §5.2's fixed codes (RS-25) —
// invalid_grant in particular never varies its body across any of its
// distinct failure causes, on either grant.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/JonasBorgesLM/usher/internal/audit"
	"github.com/JonasBorgesLM/usher/internal/identity"
	"github.com/JonasBorgesLM/usher/internal/keys"
	"github.com/JonasBorgesLM/usher/internal/oauth"
	"github.com/JonasBorgesLM/usher/internal/session"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

type tokenHandler struct {
	clients            []identity.Client
	codes              oauth.CodeStore
	families           oauth.FamilyStore
	emitter            audit.Emitter // RF-09; nil emits nothing
	keyset             *keys.Keyset
	issuer             string
	accessTokenTTL     time.Duration
	refreshIdleTTL     time.Duration
	refreshAbsoluteTTL time.Duration
	now                func() time.Time
	logger             *slog.Logger
}

// tokenErrorBody is RFC 6749 §5.2's fixed error shape.
type tokenErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// tokenSuccessBody is RFC 6749 §5.1's response. RefreshToken is empty,
// and so omitted, on a refresh_token grant whose own request narrowed
// scope to something that no longer includes offline_access — this
// project does not special-case that; RefreshToken is populated whenever
// the handler actually issued one, full stop.
type tokenSuccessBody struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// accessTokenClaims is RS-07's full claim set for an access token:
// iss/aud/exp/nbf/iat/jti, plus sub, client_id and scope, which RFC 9068
// requires even though RS-07's own list does not spell them out
// separately. typ: at+jwt (RS-07, RS-08) lives in the JWS protected
// header, per RFC 9068 — not here.
type accessTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope,omitempty"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JTI       string   `json:"jti"`
}

func (h *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	grantType := r.PostForm.Get("grant_type")
	if grantType != "authorization_code" && grantType != "refresh_token" {
		h.writeError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	client, errCode := authenticateClient(h.clients, r)
	if errCode != "" {
		if errCode == "invalid_client" {
			w.Header().Set("WWW-Authenticate", `Basic realm="usher"`)
			h.writeError(w, http.StatusUnauthorized, errCode)
			return
		}
		h.writeError(w, http.StatusBadRequest, errCode)
		return
	}

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCode(w, r, client)
	case "refresh_token":
		h.handleRefreshToken(w, r, client)
	}
}

// handleAuthorizationCode is RF-02 Flow 2 (docs/ARCHITECTURE.md §11).
func (h *tokenHandler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request, client identity.Client) {
	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")
	if code == "" || redirectURI == "" || verifier == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	issued, err := oauth.ConsumeCode(r.Context(), h.codes, h.families, code, client.ID, redirectURI, verifier)
	if err != nil {
		if errors.Is(err, oauth.ErrInvalidGrant) {
			h.writeError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		h.logger.ErrorContext(r.Context(), "token: consume code", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	accessToken, err := h.issueAccessToken(client, issued.Subject, issued.Scope)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "token: issue access token", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	// RF-02 Flow 2 steps 6-7: a client whose grant_types include
	// refresh_token also gets one, and the code that produced it is
	// tombstoned against the new family only now, after issuance
	// succeeds — the same "as late as possible" reasoning
	// CodeStore.Tombstone's own doc comment already gives.
	var refreshToken string
	if slices.Contains(client.GrantTypes, "refresh_token") {
		refreshRaw, err := session.NewRawID()
		if err != nil {
			h.logger.ErrorContext(r.Context(), "token: generate refresh token", "error", err)
			h.writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		now := h.now()
		familyID, err := h.families.CreateFamily(r.Context(),
			oauth.Family{ClientID: client.ID, Subject: issued.Subject, Scope: issued.Scope, ExpiresAt: now.Add(h.refreshAbsoluteTTL)},
			oauth.RefreshToken{Hash: sha256.Sum256([]byte(refreshRaw)), ExpiresAt: now.Add(h.refreshIdleTTL)},
		)
		if err != nil {
			h.logger.ErrorContext(r.Context(), "token: create refresh family", "error", err)
			h.writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if err := h.codes.Tombstone(r.Context(), code, familyID, h.accessTokenTTL); err != nil {
			h.logger.ErrorContext(r.Context(), "token: tombstone code", "error", err)
			h.writeError(w, http.StatusInternalServerError, "server_error")
			return
		}
		refreshToken = refreshRaw
	}

	h.writeSuccess(w, r, accessToken, refreshToken, issued.Scope)
}

// handleRefreshToken is RF-04 Flow 3 (docs/ARCHITECTURE.md §12): RS-34's
// bindings (same client_id, requested scope a subset of the family's
// own), then RotateRefreshToken's atomic rotation and reuse detection
// (#36).
func (h *tokenHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request, client identity.Client) {
	presented := r.PostForm.Get("refresh_token")
	if presented == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	hash := sha256.Sum256([]byte(presented))

	fam, _, err := h.families.Lookup(r.Context(), hash)
	if err != nil {
		if errors.Is(err, oauth.ErrRefreshTokenNotFound) {
			h.writeError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		h.logger.ErrorContext(r.Context(), "token: look up refresh token", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	// RS-34: a revoked family, or one issued to a different client, is
	// invalid_grant -- indistinguishable from "never existed," same as
	// every other cause ConsumeCode's own invalid_grant already covers.
	if fam.RevokedAt != nil || fam.ClientID != client.ID {
		h.writeError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	scope := fam.Scope
	if requested := splitScope(r.PostForm.Get("scope")); len(requested) > 0 {
		if !scopeSubset(requested, fam.Scope) {
			h.writeError(w, http.StatusBadRequest, "invalid_scope")
			return
		}
		scope = requested
	}

	nextRaw, err := session.NewRawID()
	if err != nil {
		h.logger.ErrorContext(r.Context(), "token: generate next refresh token", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	next := oauth.RefreshToken{Hash: sha256.Sum256([]byte(nextRaw)), FamilyID: fam.ID, ExpiresAt: h.now().Add(h.refreshIdleTTL)}

	if rotateErr := oauth.RotateRefreshToken(r.Context(), h.families, h.emitter, hash, next); rotateErr != nil {
		if errors.Is(rotateErr, oauth.ErrInvalidGrant) {
			h.writeError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		h.logger.ErrorContext(r.Context(), "token: rotate refresh token", "error", rotateErr)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	accessToken, err := h.issueAccessToken(client, fam.Subject, scope)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "token: issue access token", "error", err)
		h.writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	h.writeSuccess(w, r, accessToken, nextRaw, scope)
}

// issueAccessToken signs a fresh access token for subject under client,
// shared by both grants (RF-02 Flow 2 step 5 and RF-04 Flow 3 step 7).
func (h *tokenHandler) issueAccessToken(client identity.Client, subject string, scope []string) ([]byte, error) {
	key, err := h.keyset.Signing(h.now())
	if err != nil {
		return nil, fmt.Errorf("resolve signing key: %w", err)
	}
	jti, err := session.NewRawID()
	if err != nil {
		return nil, fmt.Errorf("generate jti: %w", err)
	}
	now := h.now()
	claims := accessTokenClaims{
		Issuer:    h.issuer,
		Subject:   subject,
		Audience:  client.Audiences,
		ClientID:  client.ID,
		Scope:     strings.Join(scope, " "),
		ExpiresAt: now.Add(h.accessTokenTTL).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		JTI:       jti,
	}
	return signAccessToken(key, claims)
}

func (h *tokenHandler) writeSuccess(w http.ResponseWriter, r *http.Request, accessToken []byte, refreshToken string, scope []string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(tokenSuccessBody{
		AccessToken:  string(accessToken),
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.accessTokenTTL.Seconds()),
		Scope:        strings.Join(scope, " "),
	}); err != nil {
		h.logger.ErrorContext(r.Context(), "token: encode response", "error", err)
	}
}

// authenticateClient is RS-16: client_secret_basic or client_secret_post,
// compared via Client.AuthenticateSecret's constant-time secret.Value
// comparison (RS-15) — never both methods in the same request (RFC 6749
// §2.3.1). A public client authenticates with neither; PKCE is what
// stands in for a secret there (RS-16's own wording). Every failure
// collapses to the same "invalid_client" regardless of which check
// failed — an unknown client_id and a wrong secret are indistinguishable
// to the caller, the same ambiguity RS-25 already requires of
// invalid_grant, applied here to client lookup instead of code
// consumption.
func authenticateClient(clients []identity.Client, r *http.Request) (client identity.Client, errCode string) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	postSecret := r.PostForm.Get("client_secret")
	if hasBasic && postSecret != "" {
		return identity.Client{}, "invalid_request"
	}

	clientID := r.PostForm.Get("client_id")
	secret := postSecret
	if hasBasic {
		clientID, secret = basicID, basicSecret
	}

	client, ok := lookupClient(clients, clientID)
	if !ok {
		return identity.Client{}, "invalid_client"
	}
	if client.Confidential && !client.AuthenticateSecret(secret) {
		return identity.Client{}, "invalid_client"
	}
	return client, ""
}

// writeError writes RFC 6749 §5.2's fixed error shape through
// writeOAuthError — shared with revokeHandler (#38) so /revoke's own
// client-authentication failures carry exactly the same wire shape
// /token's do, not a second, independently maintained copy of it.
func (h *tokenHandler) writeError(w http.ResponseWriter, status int, errCode string) {
	writeOAuthError(w, h.logger, status, errCode)
}

// writeOAuthError writes RFC 6749 §5.2's fixed error shape with no
// error_description (RS-25: no internal detail) — every call site across
// this package passes the same nothing, so the field exists on the wire
// type for spec completeness without a parameter here that would always
// carry one value.
func writeOAuthError(w http.ResponseWriter, logger *slog.Logger, status int, errCode string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(tokenErrorBody{Error: errCode}); err != nil {
		logger.Error("oauth: encode error response", "error", err)
	}
}

// signAccessToken builds the RS-07 claim set into a compact JWS: typ:
// at+jwt in the protected header (RFC 9068, RS-08), key's own kid carried
// automatically (RS-09, proven for this exact call shape by
// TestKey_SigningProducesKIDHeader in internal/keys).
func signAccessToken(key keys.Key, claims accessTokenClaims) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("token: marshal claims: %w", err)
	}

	signingJWK, err := key.JWK()
	if err != nil {
		return nil, fmt.Errorf("token: build signing JWK: %w", err)
	}

	hdrs := jws.NewHeaders()
	if setErr := hdrs.Set(jws.TypeKey, "at+jwt"); setErr != nil {
		return nil, fmt.Errorf("token: set typ header: %w", setErr)
	}

	var alg jwa.SignatureAlgorithm
	switch key.Algorithm {
	case tokenvalidator.RS256:
		alg = jwa.RS256()
	case tokenvalidator.ES256:
		alg = jwa.ES256()
	default:
		return nil, fmt.Errorf("token: signing key %q uses unsupported algorithm %q", key.KID, key.Algorithm)
	}

	signed, err := jws.Sign(payload, jws.WithKey(alg, signingJWK, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return nil, fmt.Errorf("token: sign access token: %w", err)
	}
	return signed, nil
}
