// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
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

const (
	TokenDuration        = 5 * time.Minute
	RefreshTokenDuration = 30 * 24 * time.Hour

	// NotValidBeforeClockSkew is the delta between the nbf and iat
	// claims to account for clock skew between servers and clients
	// 5 minutes is a typical value with 10 seconds being a common minimum
	NotValidBeforeClockSkew = 5 * time.Minute
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

	// Email is the "emailish" value with an '@' sign. Emailish values like user@github or user@passkey
	// will have the tsidp instance's hostname appened to them.
	// Example: user@github becomes user@github.<tsidp-hostname>.<tsname>.ts.net
	// Example: user@passkey becomes user@passkey.<tsidp-hostname>.<tsname>.ts.net
	Email  string         `json:"email,omitempty"`
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

// serveToken is the main /token endpoint handler
// Migrated from legacy/tsidp.go:921-942
func (s *IDPServer) serveToken(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != "POST" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
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
			writeHTTPError(w, r, http.StatusBadRequest, ecUnsupportedGrant, "token exchange not enabled", nil)
			return
		}
		s.serveTokenExchange(w, r)
	default:
		writeHTTPError(w, r, http.StatusBadRequest, ecUnsupportedGrant, "unsupported grant type",
			fmt.Errorf("unsupported grant type %q", grantType))
	}
}

// handleAuthorizationCodeGrant handles the authorization code grant type
// Migrated from legacy/tsidp.go:1212-1267
func (s *IDPServer) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "code is required", nil)
		return
	}
	s.mu.Lock()
	ar, ok := s.code[code]
	if ok {
		delete(s.code, code)
	}
	s.mu.Unlock()
	if !ok {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidGrant, "code not found", nil)
		return
	}
	if httpStatusCode, err := ar.allowRelyingParty(r); err != nil {
		writeHTTPError(w, r, httpStatusCode, ecInvalidClient, "client authentication failed", err)
		return
	}
	if ar.RedirectURI != r.FormValue("redirect_uri") {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "redirect_uri mismatch",
			fmt.Errorf("got redirect_uri %q, want %q", r.FormValue("redirect_uri"), ar.RedirectURI))
		return
	}

	// PKCE validation (RFC 7636)
	if ar.CodeChallenge != "" {
		codeVerifier := r.FormValue("code_verifier")
		if codeVerifier == "" {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "code_verifier is required", nil)
			return
		}

		if err := validateCodeVerifier(codeVerifier, ar.CodeChallenge, ar.CodeChallengeMethod); err != nil {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidGrant, "code verification failed", err)
			return
		}
	}

	// RFC 8707: Check for resource parameter in token request
	resources := r.Form["resource"]
	if len(resources) > 0 {
		// Validate requested resources using the same capability would be used for STS
		validatedResources, err := s.validateResourcesForUser(ar.RemoteUser, resources)
		if err != nil {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "invalid resource", err)
			return
		}
		ar.Resources = validatedResources
	}
	// If no resources in token request, use the ones from authorization

	s.issueTokens(w, r, ar)
}

// handleRefreshTokenGrant handles the refresh token grant type
// Migrated from legacy/tsidp.go:1269-1337
func (s *IDPServer) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	rt := r.FormValue("refresh_token")
	if rt == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "refresh_token is required", nil)
		return
	}

	s.mu.Lock()
	ar, ok := s.refreshToken[rt]
	if ok && ar.ValidTill.Before(time.Now()) {
		ok = false
	}

	// Delete the refresh token so it can not be reused. It is intentional that
	// refresh tokens can only be used once to prevent various race conditions.
	// If the response is an error the user will have to reauthenticate.
	delete(s.refreshToken, rt)

	s.mu.Unlock()

	if !ok {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidGrant, "invalid refresh token", nil)
		return
	}

	// Validate client authentication
	if httpStatusCode, err := ar.allowRelyingParty(r); err != nil {
		writeHTTPError(w, r, httpStatusCode, ecInvalidClient, "client authentication failed", err)
		return
	}

	// RFC 8707: Check for resource parameter in refresh token request
	resources := r.Form["resource"]
	if len(resources) > 0 {
		// Validate requested resources are a subset of original grant
		validatedResources, err := s.validateResourcesForUser(ar.RemoteUser, resources)
		if err != nil {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "resource validation failed", err)
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
					writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "requested resource not in original grant", nil)
					return
				}
			}
		}

		// Create a copy of authRequest with downscoped resources
		arCopy := *ar
		arCopy.Resources = validatedResources
		ar = &arCopy
	}

	s.issueTokens(w, r, ar)
}

// serveTokenExchange implements the OIDC STS token exchange flow per RFC 8693
// Migrated from legacy/tsidp.go:1012-1210
func (s *IDPServer) serveTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "failed to parse form", err)
		return
	}

	// Validate required parameters
	subjectToken := r.FormValue("subject_token")
	if subjectToken == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "subject_token is required", nil)
		return
	}

	subjectTokenType := r.FormValue("subject_token_type")
	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "unsupported subject_token_type", nil)
		return
	}

	requestedTokenType := r.FormValue("requested_token_type")
	if requestedTokenType != "" && requestedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "unsupported requested_token_type", nil)
		return
	}

	// Parse multiple audience parameters (RFC 8693 allows multiple)
	audiences := r.Form["audience"]
	if len(audiences) == 0 {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "audience is required", nil)
		return
	}

	// Identify the client performing the exchange
	exchangingClientID := s.identifyClient(r)
	if exchangingClientID == "" {
		writeHTTPError(w, r, http.StatusUnauthorized, ecInvalidClient, "invalid client credentials", nil)
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
		writeHTTPError(w, r, http.StatusUnauthorized, ecInvalidGrant, "invalid subject token", nil)
		return
	}

	if ar.ValidTill.Before(time.Now()) {
		writeHTTPError(w, r, http.StatusUnauthorized, ecInvalidGrant, "subject token expired", nil)
		return
	}

	// Check ACL grant for STS token exchange
	who := ar.RemoteUser
	rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, "tailscale.com/cap/tsidp")
	if err != nil {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "failed to unmarshal STS capability", err)
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
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "access denied for requested audience", nil)
		return
	}

	// Handle actor token for delegation (RFC 8693 Section 4.1)
	var actorInfo *ActorClaim
	if actorTokenParam := r.FormValue("actor_token"); actorTokenParam != "" {
		actorTokenType := r.FormValue("actor_token_type")
		if actorTokenType != "" && actorTokenType != "urn:ietf:params:oauth:token-type:access_token" {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "unsupported actor_token_type", nil)
			return
		}

		// Validate and add actor information
		s.mu.Lock()
		actorAR, ok := s.accessToken[actorTokenParam]
		s.mu.Unlock()
		if !ok || actorAR.ValidTill.Before(time.Now()) {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "invalid or expired actor_token", nil)
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
	iat := time.Now()
	nbf := iat.Add(-NotValidBeforeClockSkew)
	exp := iat.Add(TokenDuration)

	// Create new auth request with proper metadata for exchanged token
	newAR := &AuthRequest{
		ClientID:         exchangingClientID,
		IsExchangedToken: true,
		OriginalClientID: ar.ClientID,
		ExchangedBy:      exchangingClientID,
		Audiences:        allowedAudiences,
		IssuedAt:         iat,
		ValidTill:        exp,
		NotValidBefore:   nbf,
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
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "internal server error", err)
	}
}

// issueTokens issues access and refresh tokens
func (s *IDPServer) issueTokens(w http.ResponseWriter, r *http.Request, ar *AuthRequest) {
	signer, err := s.oidcSigner()
	if err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "internal server error - could not get signer", err)
		return
	}
	jti := rands.HexString(32)
	who := ar.RemoteUser

	n := who.Node.View()
	if n.IsTagged() {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "tagged nodes not supported", nil)
		return
	}

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

	// values for exp, nbp and iat claims
	iat := time.Now()
	exp := iat.Add(TokenDuration)
	nbf := iat.Add(-NotValidBeforeClockSkew)

	_, tcd, _ := strings.Cut(n.Name(), ".")

	tsClaims := tailscaleClaims{
		Claims: jwt.Claims{
			Audience:  audience,
			IssuedAt:  jwt.NewNumericDate(iat),
			Expiry:    jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(nbf),
			ID:        jti,
			Issuer:    s.serverURL,
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
			tsClaims.Email = s.realishEmail(who.UserProfile.LoginName)
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
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "failed to unmarshal capability", err)
		return
	}

	tsClaimsWithExtra, err := withExtraClaims(tsClaims.toMap(), rules)
	if err != nil {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "failed to merge extra claims", err)
		return
	}

	// Include act claim if present (RFC 8693 Section 4.1)
	if ar.ActorInfo != nil {
		tsClaimsWithExtra["act"] = ar.ActorInfo
	}

	// Create an OIDC token using this issuer's signer.
	token, err := jwt.Signed(signer).Claims(tsClaimsWithExtra).CompactSerialize()
	if err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "error creating JWT token", err)
		return
	}

	// Add new access token and refresh token to the token store
	at := rands.HexString(32)
	rt := rands.HexString(32)

	s.mu.Lock()
	ar.IssuedAt = iat
	ar.ValidTill = exp
	ar.NotValidBefore = nbf
	ar.JTI = jti // Store the JWT ID for introspection
	mak.Set(&s.accessToken, at, ar)

	// Create a refresh token from the access token with longer validity
	rtAuth := *ar // copy the authRequest
	rtAuth.ValidTill = iat.Add(RefreshTokenDuration)
	mak.Set(&s.refreshToken, rt, &rtAuth)
	s.mu.Unlock()

	slog.Info("token issued",
		slog.String("for", who.UserProfile.LoginName),
		slog.String("uid", n.User().String()),
		slog.String("client_id", ar.ClientID),
		slog.String("redirect_uri", ar.RedirectURI),
	)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(oidcTokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    5 * 60,
		IDToken:      token,
		RefreshToken: rt,
	}); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "internal server error", err)
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
	rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, "tailscale.com/cap/tsidp")
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

	if subtle.ConstantTimeCompare([]byte(generatedChallenge), []byte(challenge)) != 1 {
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

// serveIntrospect handles the /introspect endpoint for token introspection (RFC 7662)
// Migrated from legacy/tsidp.go:1475-1602
func (s *IDPServer) serveIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
		return
	}

	// Parse the token parameter
	token := r.FormValue("token")
	if token == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "token is required", nil)
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
		resp["iat"] = ar.IssuedAt.Unix()
		resp["nbf"] = ar.NotValidBefore.Unix()
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
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to encode response", err)
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
