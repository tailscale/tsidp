// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"tailscale.com/ipn"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
	"tailscale.com/util/rands"
)

// openIDProviderMetadata is a partial representation of OpenID Provider Metadata.
// Migrated from legacy/tsidp.go:1754-1771
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
// Migrated from legacy/tsidp.go:1773-1790
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
// Migrated from legacy/tsidp.go:1816-1845
var (
	openIDSupportedClaims = views.SliceOf([]string{
		// Standard claims, these correspond to fields in jwt.Claims.
		"sub", "aud", "exp", "iat", "iss", "jti", "nbf", "preferred_username", "email", "picture", "azp",

		// Tailscale claims
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
// Migrated from legacy/tsidp.go:1847-1923
func (s *IDPServer) serveOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Method", "GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	// early return for pre-flight OPTIONS requests.
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path != "/.well-known/openid-configuration" {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		log.Printf("Error parsing remote addr: %v", err)
		http.Error(w, "tsidp: invalid remote address", http.StatusBadRequest)
		return
	}
	var authorizeEndpoint string
	rpEndpoint := s.serverURL
	if isFunnelRequest(r) {
		authorizeEndpoint = fmt.Sprintf("%s/authorize/funnel", s.serverURL)
	} else if ap.Addr().IsLoopback() {
		rpEndpoint = s.loopbackURL
		authorizeEndpoint = fmt.Sprintf("%s/authorize/localhost", s.serverURL)
	} else if s.lc != nil {
		if who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr); err == nil {
			authorizeEndpoint = fmt.Sprintf("%s/authorize/%d", s.serverURL, who.Node.ID)
		} else {
			log.Printf("Error getting WhoIs: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "tsidp: internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	metadata := openIDProviderMetadata{
		AuthorizationEndpoint:            authorizeEndpoint,
		Issuer:                           rpEndpoint,
		JWKS_URI:                         rpEndpoint + "/.well-known/jwks.json",
		UserInfoEndpoint:                 rpEndpoint + "/userinfo",
		TokenEndpoint:                    rpEndpoint + "/token",
		IntrospectionEndpoint:            rpEndpoint + "/introspect",
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
		metadata.RegistrationEndpoint = rpEndpoint + "/register"
	}

	if err := je.Encode(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// serveOAuthMetadata serves the OAuth 2.0 Authorization Server metadata endpoint
// Migrated from legacy/tsidp.go:1925-2001
func (s *IDPServer) serveOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Method", "GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	// early return for pre-flight OPTIONS requests.
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path != "/.well-known/oauth-authorization-server" {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		log.Printf("Error parsing remote addr: %v", err)
		http.Error(w, "tsidp: invalid remote address", http.StatusBadRequest)
		return
	}
	var authorizeEndpoint string
	rpEndpoint := s.serverURL
	if isFunnelRequest(r) {
		authorizeEndpoint = fmt.Sprintf("%s/authorize/funnel", s.serverURL)
	} else if ap.Addr().IsLoopback() {
		rpEndpoint = s.loopbackURL
		authorizeEndpoint = fmt.Sprintf("%s/authorize/localhost", s.serverURL)
	} else if s.lc != nil {
		if who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr); err == nil {
			authorizeEndpoint = fmt.Sprintf("%s/authorize/%d", s.serverURL, who.Node.ID)
		} else {
			log.Printf("Error getting WhoIs: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "tsidp: internal server error", http.StatusInternalServerError)
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
		Issuer:                             rpEndpoint,
		AuthorizationEndpoint:              authorizeEndpoint,
		TokenEndpoint:                      rpEndpoint + "/token",
		IntrospectionEndpoint:              rpEndpoint + "/introspect",
		JWKS_URI:                           rpEndpoint + "/.well-known/jwks.json",
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
		metadata.RegistrationEndpoint = rpEndpoint + "/register"
	}

	if err := je.Encode(metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// serveJWKS serves the JSON Web Key Set endpoint
// Migrated from legacy/tsidp.go:1723-1750
func (s *IDPServer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/jwks.json" {
		writeJSONError(w, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	sk, err := s.oidcPrivateKey()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "internal server error")
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
		writeJSONError(w, http.StatusInternalServerError, "server_error", "internal server error")
	}
}

// Helper functions

// isFunnelRequest checks if the request is coming through Tailscale Funnel
// Migrated from legacy/tsidp.go:2392-2410
func isFunnelRequest(r *http.Request) bool {
	// If we're funneling through the local tailscaled, it will set this HTTP header
	if r.Header.Get("Tailscale-Funnel-Request") != "" {
		return true
	}

	// If the funneled connection is from tsnet, then the net.Conn will be of type ipn.FunnelConn
	netConn := r.Context().Value(CtxConn{})
	// if the conn is wrapped inside TLS, unwrap it
	if tlsConn, ok := netConn.(*tls.Conn); ok {
		netConn = tlsConn.NetConn()
	}
	if _, ok := netConn.(*ipn.FunnelConn); ok {
		return true
	}
	return false
}

// writeJSONError writes a JSON error response
// Migrated from legacy/tsidp.go:1619-1626
func writeJSONError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(oauthErrorResponse{
		Error:            errorCode,
		ErrorDescription: errorDescription,
	})
}

// oauthErrorResponse represents an OAuth 2.0 error response
// Migrated from legacy/tsidp.go:1613-1617
type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// serveClients handles the /clients/ endpoints for managing OAuth clients
// Migrated from legacy/tsidp.go:2055-2094
func (s *IDPServer) serveClients(w http.ResponseWriter, r *http.Request) {
	if isFunnelRequest(r) {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/clients/")

	if path == "new" {
		s.serveNewClient(w, r)
		return
	}

	if path == "" {
		s.serveGetClientsList(w, r)
		return
	}

	s.mu.Lock()
	c, ok := s.funnelClients[path]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "DELETE":
		s.serveDeleteClient(w, r, path)
	case "GET":
		json.NewEncoder(w).Encode(&FunnelClient{
			ID:           c.ID,
			Name:         c.Name,
			Secret:       "",
			RedirectURIs: c.RedirectURIs,
		})
	default:
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
	}
}

// serveNewClient creates a new OAuth client
// Migrated from legacy/tsidp.go:2096-2126
func (s *IDPServer) serveNewClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "tsidp: must provide redirect_uri", http.StatusBadRequest)
		return
	}
	clientID := rands.HexString(32)
	clientSecret := rands.HexString(64)
	newClient := FunnelClient{
		ID:           clientID,
		Secret:       clientSecret,
		Name:         r.FormValue("name"),
		RedirectURIs: []string{redirectURI},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mak.Set(&s.funnelClients, clientID, &newClient)
	if err := s.storeFunnelClientsLocked(); err != nil {
		log.Printf("could not write funnel clients db: %v", err)
		http.Error(w, "tsidp: could not write funnel clients to db", http.StatusInternalServerError)
		// delete the new client to avoid inconsistent state between memory
		// and disk
		delete(s.funnelClients, clientID)
		return
	}
	json.NewEncoder(w).Encode(newClient)
}

// serveGetClientsList returns a list of all OAuth clients
// Migrated from legacy/tsidp.go:2128-2145
func (s *IDPServer) serveGetClientsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	redactedClients := make([]FunnelClient, 0, len(s.funnelClients))
	for _, c := range s.funnelClients {
		redactedClients = append(redactedClients, FunnelClient{
			ID:           c.ID,
			Name:         c.Name,
			Secret:       "",
			RedirectURIs: c.RedirectURIs,
		})
	}
	s.mu.Unlock()
	json.NewEncoder(w).Encode(redactedClients)
}

// serveDeleteClient deletes an OAuth client
// Migrated from legacy/tsidp.go:2239-2265
func (s *IDPServer) serveDeleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	if r.Method != "DELETE" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.funnelClients == nil {
		http.Error(w, "tsidp: client not found", http.StatusNotFound)
		return
	}
	if _, ok := s.funnelClients[clientID]; !ok {
		http.Error(w, "tsidp: client not found", http.StatusNotFound)
		return
	}
	deleted := s.funnelClients[clientID]
	delete(s.funnelClients, clientID)
	if err := s.storeFunnelClientsLocked(); err != nil {
		log.Printf("could not write funnel clients db: %v", err)
		http.Error(w, "tsidp: could not write funnel clients to db", http.StatusInternalServerError)
		// restore the deleted value to avoid inconsistent state between memory
		// and disk
		s.funnelClients[clientID] = deleted
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// serveDynamicClientRegistration handles OAuth 2.0 Dynamic Client Registration (RFC 7591)
// Migrated from legacy/tsidp.go:2149-2237
func (s *IDPServer) serveDynamicClientRegistration(w http.ResponseWriter, r *http.Request) {
	// Block funnel requests - dynamic registration is only available over tailnet
	if isFunnelRequest(r) {
		writeJSONError(w, http.StatusForbidden, "access_denied", "dynamic client registration not available over funnel")
		return
	}

	if r.Method != "POST" {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	// Parse registration request
	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
		GrantTypes              []string `json:"grant_types,omitempty"`
		ResponseTypes           []string `json:"response_types,omitempty"`
		ClientName              string   `json:"client_name,omitempty"`
		ClientURI               string   `json:"client_uri,omitempty"`
		LogoURI                 string   `json:"logo_uri,omitempty"`
		Scope                   string   `json:"scope,omitempty"`
		Contacts                []string `json:"contacts,omitempty"`
		ApplicationType         string   `json:"application_type,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	// Validate required fields per RFC 7591 and OpenID specs
	if len(req.RedirectURIs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
		return
	}

	// Set defaults per specs
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.ApplicationType == "" {
		req.ApplicationType = "web"
	}

	// Generate client credentials
	clientID := rands.HexString(32)
	clientSecret := rands.HexString(64)

	// Create new client
	newClient := FunnelClient{
		ID:                      clientID,
		Secret:                  clientSecret,
		Name:                    req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		Scope:                   req.Scope,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		Contacts:                req.Contacts,
		ApplicationType:         req.ApplicationType,
		DynamicallyRegistered:   true,
		CreatedAt:               time.Now(),
	}

	// Store the client
	s.mu.Lock()
	mak.Set(&s.funnelClients, clientID, &newClient)
	if err := s.storeFunnelClientsLocked(); err != nil {
		s.mu.Unlock()
		log.Printf("tsidp: error storing client: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	s.mu.Unlock()

	// Return the client registration response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newClient)
}
