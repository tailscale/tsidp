// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"gopkg.in/square/go-jose.v2"
	"tailscale.com/types/views"
)

// openIDProviderMetadata is a partial representation of OpenID Provider Metadata.
type openIDProviderMetadata struct {
	Issuer                           string              `json:"issuer"`
	AuthorizationEndpoint            string              `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                    string              `json:"token_endpoint,omitempty"`
	UserInfoEndpoint                 string              `json:"userinfo_endpoint,omitempty"`
	IntrospectionEndpoint            string              `json:"introspection_endpoint,omitempty"`
	RegistrationEndpoint             string              `json:"registration_endpoint,omitempty"`
	JWKS_URI                         string              `json:"jwks_uri"`
	ScopesSupported                  views.Slice[string] `json:"scopes_supported"`
	ResponseTypesSupported           views.Slice[string] `json:"response_types_supported"`
	SubjectTypesSupported            views.Slice[string] `json:"subject_types_supported"`
	ClaimsSupported                  views.Slice[string] `json:"claims_supported"`
	IDTokenSigningAlgValuesSupported views.Slice[string] `json:"id_token_signing_alg_values_supported"`
	GrantTypesSupported              views.Slice[string] `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported    views.Slice[string] `json:"code_challenge_methods_supported,omitempty"`
}

// oauthAuthorizationServerMetadata is a representation of
// OAuth 2.0 Authorization Server Metadata as defined in RFC 8414.
type oauthAuthorizationServerMetadata struct {
	Issuer                             string              `json:"issuer"`
	AuthorizationEndpoint              string              `json:"authorization_endpoint"`
	TokenEndpoint                      string              `json:"token_endpoint"`
	IntrospectionEndpoint              string              `json:"introspection_endpoint,omitempty"`
	RegistrationEndpoint               string              `json:"registration_endpoint,omitempty"`
	JWKS_URI                           string              `json:"jwks_uri"`
	ResponseTypesSupported             views.Slice[string] `json:"response_types_supported"`
	GrantTypesSupported                views.Slice[string] `json:"grant_types_supported"`
	ScopesSupported                    views.Slice[string] `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported  views.Slice[string] `json:"token_endpoint_auth_methods_supported"`
	AuthorizationDetailsTypesSupported views.Slice[string] `json:"authorization_details_types_supported,omitempty"`
	ResourceIndicatorsSupported        bool                `json:"resource_indicators_supported,omitempty"`
	CodeChallengeMethodsSupported      views.Slice[string] `json:"code_challenge_methods_supported,omitempty"`
}

// Supported OpenID/OAuth metadata constants
var (
	openIDSupportedClaims = views.SliceOf([]string{
		// Standard claims, these correspond to fields in jwt.Claims.
		"sub", "aud", "exp", "iat", "iss", "jti", "nbf", "username", "email",

		// Tailscale claims, these correspond to fields in tailscaleClaims.
		"key", "addresses", "nid", "node", "tailnet", "tags", "user", "uid",
	})

	// As defined in the OpenID spec this should be "openid".
	openIDSupportedScopes = views.SliceOf([]string{"openid", "email", "profile"})

	// We only support getting the id_token.
	openIDSupportedReponseTypes = views.SliceOf([]string{"id_token", "code"})

	// The type of the "sub" field in the JWT, which means it is globally unique identifier.
	openIDSupportedSubjectTypes = views.SliceOf([]string{"public"})

	// The algo used for signing. The OpenID spec says "The algorithm RS256 MUST be included."
	openIDSupportedSigningAlgos = views.SliceOf([]string{string(jose.RS256)})

	// OAuth 2.0 specific metadata constants
	oauthSupportedGrantTypes               = views.SliceOf([]string{"authorization_code", "refresh_token"})
	oauthSupportedTokenEndpointAuthMethods = views.SliceOf([]string{"client_secret_post", "client_secret_basic"})

	// PKCE support (RFC 7636)
	pkceCodeChallengeMethodsSupported = views.SliceOf([]string{"plain", "S256"})
)

// serveOpenIDConfig serves the OpenID Connect discovery endpoint
func (s *IDPServer) serveOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	// early return for pre-flight OPTIONS requests.
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	metadata := openIDProviderMetadata{
		AuthorizationEndpoint:            s.serverURL + "/authorize",
		Issuer:                           s.serverURL,
		JWKS_URI:                         s.serverURL + "/.well-known/jwks.json",
		UserInfoEndpoint:                 s.serverURL + "/userinfo",
		TokenEndpoint:                    s.serverURL + "/token",
		IntrospectionEndpoint:            s.serverURL + "/introspect",
		ScopesSupported:                  openIDSupportedScopes,
		ResponseTypesSupported:           openIDSupportedReponseTypes,
		SubjectTypesSupported:            openIDSupportedSubjectTypes,
		ClaimsSupported:                  openIDSupportedClaims,
		IDTokenSigningAlgValuesSupported: openIDSupportedSigningAlgos,
		CodeChallengeMethodsSupported:    pkceCodeChallengeMethodsSupported,
	}

	// Add grant types supported
	grantTypes := []string{"authorization_code", "refresh_token"}
	if s.enableSTS {
		grantTypes = append(grantTypes, "urn:ietf:params:oauth:grant-type:token-exchange")
	}
	metadata.GrantTypesSupported = views.SliceOf(grantTypes)

	// Only expose registration endpoint over tailnet, not funnel
	if !isFunnelRequest(r) {
		metadata.RegistrationEndpoint = s.serverURL + "/register"
	}

	if err := je.Encode(metadata); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to encode metadata", err)
	}
}

// serveOAuthMetadata serves the OAuth 2.0 Authorization Server metadata endpoint
func (s *IDPServer) serveOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	// early return for pre-flight OPTIONS requests.
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")

	// Build grant types list
	grantTypes := []string{"authorization_code", "refresh_token"}
	if s.enableSTS {
		grantTypes = append(grantTypes, "urn:ietf:params:oauth:grant-type:token-exchange")
	}

	metadata := oauthAuthorizationServerMetadata{
		Issuer:                             s.serverURL,
		AuthorizationEndpoint:              s.serverURL + "/authorize",
		TokenEndpoint:                      s.serverURL + "/token",
		IntrospectionEndpoint:              s.serverURL + "/introspect",
		JWKS_URI:                           s.serverURL + "/.well-known/jwks.json",
		ResponseTypesSupported:             openIDSupportedReponseTypes,
		GrantTypesSupported:                views.SliceOf(grantTypes),
		ScopesSupported:                    openIDSupportedScopes,
		TokenEndpointAuthMethodsSupported:  oauthSupportedTokenEndpointAuthMethods,
		ResourceIndicatorsSupported:        true, // RFC 8707 support
		AuthorizationDetailsTypesSupported: views.SliceOf([]string{"resource_indicators"}),
		CodeChallengeMethodsSupported:      pkceCodeChallengeMethodsSupported,
	}

	// Only expose registration endpoint over tailnet, not funnel
	if !isFunnelRequest(r) {
		metadata.RegistrationEndpoint = s.serverURL + "/register"
	}

	if err := je.Encode(metadata); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to encode metadata", err)
	}
}

// serveJWKS serves the JSON Web Key Set endpoint
func (s *IDPServer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	// early return for pre-flight OPTIONS requests.
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	sk, err := s.oidcPrivateKey()
	if err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "internal server error", err)
		return
	}
	// TODO(maisem): maybe only marshal this once and reuse?
	// TODO(maisem): implement key rotation.
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	if err := je.Encode(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       sk.Key.Public(),
				Algorithm: string(jose.RS256),
				Use:       "sig",
				KeyID:     fmt.Sprint(sk.Kid),
			},
		},
	}); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "internal server error", err)
	}
}
