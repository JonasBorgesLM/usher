// GET /.well-known/openid-configuration (OIDC Discovery 1.0, RS-29,
// RF-11): advertises only what this binary actually does, not what OIDC
// Core permits in general. Every field below is a fact about an already
// -built handler elsewhere in this package, not a new behavior this file
// introduces -- discoveryBody has no logic of its own to get wrong,
// which is deliberate: a discovery document that could itself diverge
// from the server it describes would be worse than no document.
//
// What is absent matters as much as what is present: `implicit` and
// `password` never appear in `grant_types_supported` or
// `response_types_supported` -- both dropped from OAuth 2.1 before this
// project started (REQUIREMENTS §3.1), never a candidate. OIDC Discovery
// 1.0 itself has no metadata field for `prompt` or `max_age` support
// (RF-11, #47/#99) -- there is nothing to add here for either, not an
// omission.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

// discoveryBody is OIDC Discovery 1.0's own metadata document, narrowed
// to the fields this server can answer truthfully. There is no
// registration_endpoint (RF-01's clients are static configuration, never
// dynamically registered) and no introspection_endpoint (REQUIREMENTS
// §3.2 names RFC 7662 as a protocol surface but nothing implements it
// yet) -- both left out rather than advertised as present.
type discoveryBody struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

type discoveryHandler struct {
	issuer string
	logger *slog.Logger
}

func (h *discoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body := discoveryBody{
		Issuer:                h.issuer,
		AuthorizationEndpoint: h.issuer + "/authorize",
		TokenEndpoint:         h.issuer + "/token",
		UserinfoEndpoint:      h.issuer + "/userinfo",
		JWKSURI:               h.issuer + "/.well-known/jwks.json",
		RevocationEndpoint:    h.issuer + "/revoke",
		// "code" only: authorize.go's own response_type check (RF-02 Flow
		// 1 step 1) rejects anything else with unsupported_response_type.
		ResponseTypesSupported: []string{"code"},
		// authorization_code, refresh_token and client_credentials
		// (#49) only: token.go's own grant_type dispatch rejects
		// anything else with unsupported_grant_type -- implicit and
		// password were removed from OAuth 2.1 before this project
		// started (REQUIREMENTS §3.1).
		GrantTypesSupported: []string{"authorization_code", "refresh_token", "client_credentials"},
		// "public": sub is the raw subject (the authenticated user's own
		// id), identical across every client -- never pairwise.
		SubjectTypesSupported: []string{"public"},
		// Derived from RS-06's own allow-list (pkg/tokenvalidator), not
		// hand-typed: these two string values can never silently drift
		// from what signJWT (token.go) and ValidateAccessToken actually
		// accept.
		IDTokenSigningAlgValuesSupported: []string{
			string(tokenvalidator.RS256), string(tokenvalidator.ES256),
		},
		// authenticateClient (token.go) accepts a public client with no
		// secret at all ("none"), a confidential client's secret via
		// HTTP Basic, or via the request body -- all three, nothing
		// else.
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
		// "openid" alone: it is the only scope value this server treats
		// as meaningful anywhere (issueAccessToken's own userinfo-
		// audience gate, #45). A client's registered Scopes (RF-01) may
		// list others -- "profile", say -- but nothing in this server
		// grants any claim or behavior because of them, so advertising
		// them here would claim a capability this project does not have.
		ScopesSupported: []string{"openid"},
		// "sub" alone: userinfoBody (userinfo.go) carries nothing else,
		// for the same reason -- no name, email or other profile data
		// exists anywhere in identity.User to return.
		ClaimsSupported: []string{"sub"},
		// "S256" alone: authorize.go's own code_challenge_method check
		// (RF-02 Flow 1 step 1, RS-01) rejects anything else, including
		// "plain".
		CodeChallengeMethodsSupported: []string{"S256"},
		// RS-29: every redirect from /authorize, success or error,
		// already carries iss (oauth_errors.go's redirectWithCode and
		// redirectOAuthError) -- true today, not a plan.
		AuthorizationResponseIssParameterSupported: true,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger.ErrorContext(r.Context(), "discovery: encode response", "error", err)
	}
}
