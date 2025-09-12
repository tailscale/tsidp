// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
	"tailscale.com/util/rands"
)

// Token endpoint types
// Migrated from legacy/tsidp.go:1604-1616

type oidcTokenResponse struct {
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
}

// Claims types
// Migrated from legacy/tsidp.go:1792-1807

type tailscaleClaims struct {
	jwt.Claims `json:",inline"`
	Nonce      string                    `json:"nonce,omitempty"` // the nonce from the request
	Key        key.NodePublic            `json:"key"`             // the node public key
	Addresses  views.Slice[netip.Prefix] `json:"addresses"`       // the Tailscale IPs of the node
	NodeID     tailcfg.NodeID            `json:"nid"`             // the stable node ID
	NodeName   string                    `json:"node"`            // name of the node
	Tailnet    string                    `json:"tailnet"`         // tailnet (like tail-scale.ts.net)

	// Email is the "emailish" value with an '@' sign. It might not be a valid email.
	Email  string         `json:"email,omitempty"` // user emailish (like "alice@github" or "bob@example.com")
	UserID tailcfg.UserID `json:"uid,omitempty"`

	// PreferredUsername is the local part of Email (without '@' and domain).
	PreferredUsername string `json:"preferred_username,omitempty"`

	// Picture is the user's profile picture URL
	Picture string `json:"picture,omitempty"`

	// AuthorizedParty is the azp claim for multi-audience scenarios
	AuthorizedParty string `json:"azp,omitempty"`

	// UserName is the local part of Email (without '@' and domain).
	// It is a temporary (2023-11-15) hack during development.
	// We should probably let this be configured via grants.
	// 2025-09-08 - left in here for test compatibility
	UserName string `json:"username,omitempty"`
}

// toMap converts tailscaleClaims to a map[string]any using JSON struct tag names
// this is more reliable than marshaling to JSON for claims merging
func (tc tailscaleClaims) toMap() map[string]any {
	m := make(map[string]any)

	// Add embedded jwt.Claims fields using their JSON tag names
	if tc.Claims.Issuer != "" {
		m["iss"] = tc.Claims.Issuer
	}
	if tc.Claims.Subject != "" {
		m["sub"] = tc.Claims.Subject
	}
	if len(tc.Claims.Audience) > 0 {
		m["aud"] = tc.Claims.Audience
	}
	if tc.Claims.Expiry != nil {
		m["exp"] = tc.Claims.Expiry
	}
	if tc.Claims.NotBefore != nil {
		m["nbf"] = tc.Claims.NotBefore
	}
	if tc.Claims.IssuedAt != nil {
		m["iat"] = tc.Claims.IssuedAt
	}
	if tc.Claims.ID != "" {
		m["jti"] = tc.Claims.ID
	}

	// Add tailscale-specific fields
	if tc.Nonce != "" {
		m["nonce"] = tc.Nonce
	}
	m["key"] = tc.Key
	m["addresses"] = tc.Addresses
	m["nid"] = tc.NodeID
	if tc.NodeName != "" {
		m["node"] = tc.NodeName
	}
	if tc.Tailnet != "" {
		m["tailnet"] = tc.Tailnet
	}
	if tc.Email != "" {
		m["email"] = tc.Email
	}
	if tc.UserID != 0 {
		m["uid"] = tc.UserID
	}
	if tc.PreferredUsername != "" {
		m["preferred_username"] = tc.PreferredUsername
	}
	if tc.Picture != "" {
		m["picture"] = tc.Picture
	}
	if tc.AuthorizedParty != "" {
		m["azp"] = tc.AuthorizedParty
	}
	if tc.UserName != "" {
		m["username"] = tc.UserName
	}

	return m
}

// Capability rule types
// Migrated from legacy/tsidp.go:779-790

type capRule struct {
	IncludeInUserInfo bool           `json:"includeInUserInfo"`
	ExtraClaims       map[string]any `json:"extraClaims,omitempty"` // list of features peer is allowed to edit
}

type stsCapRule struct {
	Users     []string `json:"users"`     // list of users allowed to access resources (supports "*" wildcard)
	Resources []string `json:"resources"` // list of audience/resource URIs the user can access
}

// serveToken is the main /token endpoint handler
// Migrated from legacy/tsidp.go:921-942
func (s *IDPServer) serveToken(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Method", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		if !s.enableSTS {
			writeTokenEndpointError(w, http.StatusBadRequest, "unsupported_grant_type", "token exchange not enabled")
			return
		}
		s.serveTokenExchange(w, r)
	default:
		writeTokenEndpointError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

// handleAuthorizationCodeGrant handles the authorization code grant type
// Migrated from legacy/tsidp.go:1212-1267
func (s *IDPServer) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	s.mu.Lock()
	ar, ok := s.code[code]
	if ok {
		delete(s.code, code)
	}
	s.mu.Unlock()
	if !ok {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_grant", "code not found")
		return
	}
	if httpStatusCode, err := ar.allowRelyingParty(r); err != nil {
		//log.Printf("XXX Error allowing relying party: %v", err)
		writeTokenEndpointError(w, httpStatusCode, "invalid_client", err.Error())
		return
	}
	if ar.RedirectURI != r.FormValue("redirect_uri") {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// PKCE validation (RFC 7636)
	if ar.CodeChallenge != "" {
		codeVerifier := r.FormValue("code_verifier")
		if codeVerifier == "" {
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required")
			return
		}

		if err := validateCodeVerifier(codeVerifier, ar.CodeChallenge, ar.CodeChallengeMethod); err != nil {
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_grant", err.Error())
			return
		}
	}

	// RFC 8707: Check for resource parameter in token request
	resources := r.Form["resource"]
	if len(resources) > 0 {
		// Validate requested resources using the same capability would be used for STS
		validatedResources, err := s.validateResourcesForUser(ar.RemoteUser, resources)
		if err != nil {
			//log.Printf("Error validating resources: %v", err)
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "invalid resource")
			return
		}
		ar.Resources = validatedResources
	}
	// If no resources in token request, use the ones from authorization

	s.issueTokens(w, ar)
}

// handleRefreshTokenGrant handles the refresh token grant type
// Migrated from legacy/tsidp.go:1269-1337
func (s *IDPServer) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	rt := r.FormValue("refresh_token")
	if rt == "" {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	s.mu.Lock()
	ar, ok := s.refreshToken[rt]
	if ok && ar.ValidTill.Before(time.Now()) {
		// Token expired, remove it
		delete(s.refreshToken, rt)
		ok = false
	}
	s.mu.Unlock()

	if !ok {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}

	// Validate client authentication
	if httpStatusCode, err := ar.allowRelyingParty(r); err != nil {
		//log.Printf("Error allowing relying party: %v", err)
		writeTokenEndpointError(w, httpStatusCode, "invalid_client", err.Error())
		return
	}

	// RFC 8707: Check for resource parameter in refresh token request
	resources := r.Form["resource"]
	if len(resources) > 0 {
		// Validate requested resources are a subset of original grant
		validatedResources, err := s.validateResourcesForUser(ar.RemoteUser, resources)
		if err != nil {
			//log.Printf("Error validating resources: %v", err)
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		// Ensure requested resources are subset of original grant
		if len(ar.Resources) > 0 {
			for _, requested := range validatedResources {
				found := false
				for _, allowed := range ar.Resources {
					if requested == allowed {
						found = true
						break
					}
				}
				if !found {
					writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "requested resource not in original grant")
					return
				}
			}
		}

		// Create a copy of authRequest with downscoped resources
		arCopy := *ar
		arCopy.Resources = validatedResources
		ar = &arCopy
	}

	// Delete the old refresh token (rotation for security)
	s.mu.Lock()
	delete(s.refreshToken, rt)
	s.mu.Unlock()

	s.issueTokens(w, ar)
}

// serveTokenExchange implements the OIDC STS token exchange flow per RFC 8693
// Migrated from legacy/tsidp.go:1012-1210
func (s *IDPServer) serveTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
		return
	}

	// Validate required parameters
	subjectToken := r.FormValue("subject_token")
	if subjectToken == "" {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}

	subjectTokenType := r.FormValue("subject_token_type")
	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "unsupported subject_token_type")
		return
	}

	requestedTokenType := r.FormValue("requested_token_type")
	if requestedTokenType != "" && requestedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "unsupported requested_token_type")
		return
	}

	// Parse multiple audience parameters (RFC 8693 allows multiple)
	audiences := r.Form["audience"]
	if len(audiences) == 0 {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "audience is required")
		return
	}

	// Identify the client performing the exchange
	exchangingClientID := s.identifyClient(r)
	if exchangingClientID == "" {
		writeTokenEndpointError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	// Get the funnel client if this is a funnel client
	var exchangingFunnelClient *FunnelClient
	s.mu.Lock()
	if client, ok := s.funnelClients[exchangingClientID]; ok {
		exchangingFunnelClient = client
	}
	s.mu.Unlock()

	// Validate subject token
	s.mu.Lock()
	ar, ok := s.accessToken[subjectToken]
	s.mu.Unlock()
	if !ok {
		writeTokenEndpointError(w, http.StatusUnauthorized, "invalid_grant", "invalid subject token")
		return
	}

	if ar.ValidTill.Before(time.Now()) {
		writeTokenEndpointError(w, http.StatusUnauthorized, "invalid_grant", "subject token expired")
		return
	}

	// Check ACL grant for STS token exchange
	who := ar.RemoteUser
	rules, err := tailcfg.UnmarshalCapJSON[stsCapRule](who.CapMap, "test-tailscale.com/idp/sts/openly-allow")
	if err != nil {
		//log.Printf("tsidp: failed to unmarshal STS capability: %v", err)
		writeTokenEndpointError(w, http.StatusForbidden, "access_denied", fmt.Sprintf("failed to unmarshal STS capability: %s", err.Error()))
		return
	}

	// Check if user is allowed to exchange tokens for the requested audiences
	allowedAudiences := []string{}
	for _, audience := range audiences {
		allowed := false
		for _, rule := range rules {
			// Check if user matches (support wildcard or specific user)
			userMatches := false
			for _, user := range rule.Users {
				if user == "*" || user == who.UserProfile.LoginName {
					userMatches = true
					break
				}
			}

			if userMatches {
				// Check if audience/resource matches
				for _, resource := range rule.Resources {
					if resource == audience || resource == "*" {
						allowed = true
						break
					}
				}
			}

			if allowed {
				break
			}
		}
		if allowed {
			allowedAudiences = append(allowedAudiences, audience)
		}
	}

	if len(allowedAudiences) == 0 {
		writeTokenEndpointError(w, http.StatusForbidden, "access_denied", "access denied for requested audience")
		return
	}

	// Handle actor token for delegation (RFC 8693 Section 4.1)
	var actorInfo *ActorClaim
	if actorTokenParam := r.FormValue("actor_token"); actorTokenParam != "" {
		actorTokenType := r.FormValue("actor_token_type")
		if actorTokenType != "" && actorTokenType != "urn:ietf:params:oauth:token-type:access_token" {
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "unsupported actor_token_type")
			return
		}

		// Validate and add actor information
		s.mu.Lock()
		actorAR, ok := s.accessToken[actorTokenParam]
		s.mu.Unlock()
		if !ok || actorAR.ValidTill.Before(time.Now()) {
			writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "invalid or expired actor_token")
			return
		}

		actorInfo = &ActorClaim{
			Subject:  actorAR.RemoteUser.Node.User.String(),
			ClientID: actorAR.ClientID,
			// Check if actor token itself has an actor (delegation chain)
			Actor: actorAR.ActorInfo,
		}
	}

	// Generate new access token
	newAccessToken := rands.HexString(32)

	// Create new auth request with proper metadata for exchanged token
	newAR := &AuthRequest{
		ClientID:         exchangingClientID,
		IsExchangedToken: true,
		OriginalClientID: ar.ClientID,
		ExchangedBy:      exchangingClientID,
		Audiences:        allowedAudiences,
		ValidTill:        time.Now().Add(5 * time.Minute),
		RemoteUser:       who,
		Resources:        allowedAudiences, // RFC 8707 resource indicators
		Scopes:           ar.Scopes,        // Preserve original scopes
		ActorInfo:        actorInfo,

		// Preserve original RP context
		LocalRP:  ar.LocalRP,
		RPNodeID: ar.RPNodeID,
		FunnelRP: ar.FunnelRP, // Keep original funnel client if it exists
	}

	// If the exchanger is a funnel client, also track it
	if exchangingFunnelClient != nil && ar.FunnelRP == nil {
		newAR.FunnelRP = exchangingFunnelClient
	}

	// Set redirect URI if available
	if exchangingFunnelClient != nil && len(exchangingFunnelClient.RedirectURIs) > 0 {
		newAR.RedirectURI = exchangingFunnelClient.RedirectURIs[0]
	} else if ar.RedirectURI != "" {
		newAR.RedirectURI = ar.RedirectURI
	}

	s.mu.Lock()
	mak.Set(&s.accessToken, newAccessToken, newAR)
	s.mu.Unlock()

	// Return RFC 8693 compliant response
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"access_token":      newAccessToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        300, // 5 minutes
	}

	// Only include scope if different from requested (RFC 8693)
	if requestedScope := r.FormValue("scope"); requestedScope != "" {
		actualScope := strings.Join(newAR.Scopes, " ")
		if actualScope != requestedScope {
			response["scope"] = actualScope
		}
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		writeTokenEndpointError(w, http.StatusInternalServerError, "server_error", "internal server error")
	}
}

// issueTokens issues access and refresh tokens
// Migrated from legacy/tsidp.go:1339-1473
func (s *IDPServer) issueTokens(w http.ResponseWriter, ar *AuthRequest) {
	signer, err := s.oidcSigner()
	if err != nil {
		//log.Printf("Error getting signer: %v", err)
		writeTokenEndpointError(w, http.StatusInternalServerError, "server_error", "internal server error - could not get signer")
		return
	}
	jti := rands.HexString(32)
	who := ar.RemoteUser

	n := who.Node.View()
	if n.IsTagged() {
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "tagged nodes not supported")
		return
	}

	now := time.Now()
	_, tcd, _ := strings.Cut(n.Name(), ".")

	// Build audience claim - for exchanged tokens use audiences, otherwise use clientID + resources
	var audience jwt.Audience
	if ar.IsExchangedToken && len(ar.Audiences) > 0 {
		// For exchanged tokens, use the audiences directly
		audience = jwt.Audience(ar.Audiences)
		// Also include the original client if not already in audiences
		hasOriginal := false
		for _, aud := range ar.Audiences {
			if aud == ar.OriginalClientID {
				hasOriginal = true
				break
			}
		}
		if !hasOriginal && ar.OriginalClientID != "" {
			audience = append(audience, ar.OriginalClientID)
		}
	} else {
		// Original behavior for non-exchanged tokens
		audience = jwt.Audience{ar.ClientID}
		if len(ar.Resources) > 0 {
			// Add resources to the audience list (RFC 8707)
			audience = append(audience, ar.Resources...)
		}
	}

	tsClaims := tailscaleClaims{
		Claims: jwt.Claims{
			Audience:  audience,
			Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.serverURL,
			NotBefore: jwt.NewNumericDate(now),
			Subject:   n.User().String(),
		},
		Nonce:     ar.Nonce,
		Key:       n.Key(),
		Addresses: n.Addresses(),
		NodeID:    n.ID(),
		NodeName:  n.Name(),
		Tailnet:   tcd,
		UserID:    n.User(),
	}

	// Only include email and preferred_username if the appropriate scopes were granted
	for _, scope := range ar.Scopes {
		switch scope {
		case "email":
			tsClaims.Email = who.UserProfile.LoginName
		case "profile":
			if username, _, ok := strings.Cut(who.UserProfile.LoginName, "@"); ok {
				tsClaims.PreferredUsername = username
			}
			tsClaims.Picture = who.UserProfile.ProfilePicURL
		}
	}

	// Set azp (authorized party) claim when there are multiple audiences
	// Per OIDC spec, azp is REQUIRED when the ID Token has multiple audiences
	if len(audience) > 1 {
		tsClaims.AuthorizedParty = ar.ClientID
	}

	rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, tailcfg.PeerCapabilityTsIDP)
	if err != nil {
		//log.Printf("tsidp: failed to unmarshal capability: %v", err)
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "failed to unmarshal capability")
		return
	}

	tsClaimsWithExtra, err := withExtraClaims(tsClaims.toMap(), rules)
	if err != nil {
		//log.Printf("tsidp: failed to merge extra claims: %v", err)
		writeTokenEndpointError(w, http.StatusBadRequest, "invalid_request", "failed to merge extra claims")
		return
	}

	// Include act claim if present (RFC 8693 Section 4.1)
	if ar.ActorInfo != nil {
		tsClaimsWithExtra["act"] = ar.ActorInfo
	}

	// Create an OIDC token using this issuer's signer.
	token, err := jwt.Signed(signer).Claims(tsClaimsWithExtra).CompactSerialize()
	if err != nil {
		//log.Printf("Error getting token: %v", err)
		writeTokenEndpointError(w, http.StatusInternalServerError, "server_error", "error creating token")
		return
	}

	at := rands.HexString(32)
	rt := rands.HexString(32)
	s.mu.Lock()
	ar.ValidTill = now.Add(5 * time.Minute)
	ar.JTI = jti // Store the JWT ID for introspection
	mak.Set(&s.accessToken, at, ar)
	// Create a new authRequest for refresh token with longer validity
	rtAuth := *ar                                   // copy the authRequest
	rtAuth.ValidTill = now.Add(30 * 24 * time.Hour) // 30 days
	mak.Set(&s.refreshToken, rt, &rtAuth)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(oidcTokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    5 * 60,
		IDToken:      token,
		RefreshToken: rt,
	}); err != nil {
		writeTokenEndpointError(w, http.StatusInternalServerError, "server_error", "internal server error")
	}
}

// identifyClient identifies the client making the request
// Migrated from legacy/tsidp.go:946-988
func (s *IDPServer) identifyClient(r *http.Request) string {
	// Check funnel client with Basic Auth
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		s.mu.Lock()
		client, ok := s.funnelClients[clientID]
		s.mu.Unlock()
		if ok {
			if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) == 1 {
				return clientID
			}
		}
	}

	// Check funnel client with form parameters
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID != "" && clientSecret != "" {
		s.mu.Lock()
		client, ok := s.funnelClients[clientID]
		s.mu.Unlock()
		if ok {
			if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) == 1 {
				return clientID
			}
		}
	}

	// Check local client
	ra, err := netip.ParseAddrPort(r.RemoteAddr)
	if err == nil && ra.Addr().IsLoopback() {
		return "local:" + ra.Addr().String()
	}

	// Check node client
	if s.lc != nil {
		who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
		if err == nil {
			return fmt.Sprintf("node:%d", who.Node.ID)
		}
	}

	return ""
}

// validateResourcesForUser checks if the user is allowed to access the requested resources
// Migrated from legacy/tsidp.go:426-472
func (s *IDPServer) validateResourcesForUser(who *apitype.WhoIsResponse, requestedResources []string) ([]string, error) {
	// Check ACL grant using the same capability as we would use for STS token exchange
	rules, err := tailcfg.UnmarshalCapJSON[stsCapRule](who.CapMap, "test-tailscale.com/idp/sts/openly-allow")
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal capability: %w", err)
	}

	// Filter resources based on what the user is allowed to access
	var allowedResources []string
	for _, resource := range requestedResources {
		allowed := false
		for _, rule := range rules {
			// Check if user matches (support wildcard or specific user)
			userMatches := false
			for _, user := range rule.Users {
				if user == "*" || user == who.UserProfile.LoginName {
					userMatches = true
					break
				}
			}

			if userMatches {
				// Check if resource matches
				for _, allowedResource := range rule.Resources {
					if allowedResource == resource || allowedResource == "*" {
						allowed = true
						break
					}
				}
			}

			if allowed {
				break
			}
		}
		if allowed {
			allowedResources = append(allowedResources, resource)
		}
	}

	if len(allowedResources) == 0 {
		return nil, fmt.Errorf("no valid resources")
	}

	return allowedResources, nil
}

// validateCodeVerifier validates the PKCE code verifier
// Migrated from legacy/tsidp.go:476-501
func validateCodeVerifier(verifier, challenge, method string) error {
	// Validate code_verifier format (43-128 characters, unreserved characters only)
	if len(verifier) < 43 || len(verifier) > 128 {
		return fmt.Errorf("code_verifier must be 43-128 characters")
	}

	// Check that verifier only contains unreserved characters: A-Z a-z 0-9 - . _ ~
	for _, r := range verifier {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '.' || r == '_' || r == '~') {
			return fmt.Errorf("code_verifier contains invalid characters")
		}
	}

	// Generate the challenge from the verifier and compare
	generatedChallenge, err := generateCodeChallenge(verifier, method)
	if err != nil {
		return err
	}

	if generatedChallenge != challenge {
		return fmt.Errorf("invalid code_verifier")
	}

	return nil
}

// generateCodeChallenge creates a code challenge from a code verifier using the specified method
// Migrated from legacy/tsidp.go:505-520
func generateCodeChallenge(verifier, method string) (string, error) {
	switch method {
	case "plain":
		return verifier, nil
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		// Use RawURLEncoding (no padding) as specified in RFC 7636
		return base64.RawURLEncoding.EncodeToString(h[:]), nil
	default:
		return "", fmt.Errorf("unsupported code_challenge_method: %s", method)
	}
}

// writeTokenEndpointError writes an RFC 6749 compliant token endpoint error response
// Migrated from legacy/tsidp.go:1630-1639
func writeTokenEndpointError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	//log.Printf("XXX token endpoint error: %d > %s\n", statusCode, errorDescription)
	json.NewEncoder(w).Encode(oauthErrorResponse{
		Error:            errorCode,
		ErrorDescription: errorDescription,
	})
}

// serveIntrospect handles the /introspect endpoint for token introspection (RFC 7662)
// Migrated from legacy/tsidp.go:1475-1602
func (s *IDPServer) serveIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the token parameter
	token := r.FormValue("token")
	if token == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	// token_type_hint is optional, we can ignore it for now
	// since we only have one type of token (access tokens)

	// Look up the token
	s.mu.Lock()
	ar, tokenExists := s.accessToken[token]
	s.mu.Unlock()

	// Initialize response with active: false (default for invalid/expired tokens)
	resp := map[string]any{
		"active": false,
	}

	// Check if token exists and handle expiration
	if tokenExists {
		now := time.Now()
		if ar.ValidTill.Before(now) {
			// Token expired, clean it up
			s.mu.Lock()
			delete(s.accessToken, token)
			s.mu.Unlock()
			tokenExists = false
		}
	}

	// If token exists and is not expired, we need to authenticate the client
	if tokenExists {
		// Check if the client is properly authenticated
		// Any authenticated client can introspect any token
		if s.identifyClient(r) == "" {
			// Return inactive token for unauthorized clients
			// This prevents token scanning attacks
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Token is valid and client is authorized, return active with metadata
		resp["active"] = true
		resp["client_id"] = ar.ClientID
		resp["exp"] = ar.ValidTill.Unix()
		resp["iat"] = ar.ValidTill.Add(-5 * time.Minute).Unix() // issued 5 min before expiry
		resp["nbf"] = ar.ValidTill.Add(-5 * time.Minute).Unix() // not before time (same as iat)
		resp["token_type"] = "Bearer"
		resp["iss"] = s.serverURL

		// Add jti if available
		if ar.JTI != "" {
			resp["jti"] = ar.JTI
		}

		if ar.RemoteUser != nil && ar.RemoteUser.Node != nil {
			resp["sub"] = fmt.Sprintf("%d", ar.RemoteUser.Node.User)

			// Add username claim (RFC 7662 recommendation)
			if ar.RemoteUser.UserProfile != nil && ar.RemoteUser.UserProfile.LoginName != "" {
				resp["username"] = ar.RemoteUser.UserProfile.LoginName
			}

			// Only include claims based on granted scopes
			for _, scope := range ar.Scopes {
				switch scope {
				case "profile":
					if ar.RemoteUser.UserProfile != nil {
						if username, _, ok := strings.Cut(ar.RemoteUser.UserProfile.LoginName, "@"); ok {
							resp["preferred_username"] = username
						}
						resp["picture"] = ar.RemoteUser.UserProfile.ProfilePicURL
					}
				case "email":
					if ar.RemoteUser.UserProfile != nil {
						resp["email"] = ar.RemoteUser.UserProfile.LoginName
					}
				}
			}
		}

		// Add audience - for exchanged tokens use the audiences field, otherwise build from clientID and resources
		var audience []string
		if ar.IsExchangedToken && len(ar.Audiences) > 0 {
			audience = ar.Audiences
		} else {
			if ar.ClientID != "" {
				audience = append(audience, ar.ClientID)
			}
			if len(ar.Resources) > 0 {
				audience = append(audience, ar.Resources...)
			}
		}
		if len(audience) > 0 {
			resp["aud"] = audience
		}

		// Add scope if available
		if len(ar.Scopes) > 0 {
			resp["scope"] = strings.Join(ar.Scopes, " ")
		}

		// Include act claim if present (RFC 8693)
		if ar.ActorInfo != nil {
			resp["act"] = ar.ActorInfo
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// allowRelyingParty checks if the relying party is allowed to access the token
// Migrated from legacy/tsidp.go:520-552
func (ar *AuthRequest) allowRelyingParty(r *http.Request) (int, error) {
	if ar.FunnelRP == nil {
		return http.StatusUnauthorized, fmt.Errorf("tsidp: no relying party configured")
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if clientID == "" || clientSecret == "" {
		return http.StatusUnauthorized, fmt.Errorf("tsidp: missing client credentials")
	}

	clientIDcmp := subtle.ConstantTimeCompare([]byte(clientID), []byte(ar.FunnelRP.ID))
	clientSecretcmp := subtle.ConstantTimeCompare([]byte(clientSecret), []byte(ar.FunnelRP.Secret))
	if clientIDcmp != 1 {
		return http.StatusBadRequest, fmt.Errorf("tsidp: client_id mismatch")
	}
	if clientSecretcmp != 1 {
		return http.StatusUnauthorized, fmt.Errorf("tsidp: invalid client secret: [%s] [%s]", clientID, clientSecret)
	}
	return http.StatusOK, nil
}
