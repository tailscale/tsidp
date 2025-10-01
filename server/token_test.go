// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestResourceIndicators tests RFC 8707 resource indicators support
// Migrated from legacy/tsidp_test.go:2468-2652
func TestResourceIndicators(t *testing.T) {
	tests := []struct {
		name               string
		authorizationQuery string
		tokenFormData      url.Values
		capMapRules        []capRule
		expectStatus       int
		checkResponse      func(t *testing.T, body []byte)
	}{
		{
			name:               "authorization with single resource",
			authorizationQuery: "client_id=test-client&redirect_uri=https://example.com/callback&resource=https://api.example.com",
			tokenFormData: url.Values{
				"grant_type":   {"authorization_code"},
				"redirect_uri": {"https://example.com/callback"},
			},
			capMapRules: []capRule{
				{
					Users:     []string{"*"},
					Resources: []string{"https://api.example.com"},
				},
			},
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var resp oidcTokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				// Decode JWT to check audience
				token, err := jwt.ParseSigned(resp.IDToken)
				if err != nil {
					t.Fatalf("failed to parse JWT: %v", err)
				}
				var claims map[string]interface{}
				if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
					t.Fatalf("failed to get claims: %v", err)
				}
				aud, ok := claims["aud"].([]interface{})
				if !ok {
					t.Fatalf("expected aud to be an array, got %T", claims["aud"])
				}
				if len(aud) != 2 || aud[0] != "test-client" || aud[1] != "https://api.example.com" {
					t.Errorf("expected audience [test-client, https://api.example.com], got %v", aud)
				}
			},
		},
		{
			name:               "authorization with multiple resources",
			authorizationQuery: "client_id=test-client&redirect_uri=https://example.com/callback&resource=https://api1.example.com&resource=https://api2.example.com",
			tokenFormData: url.Values{
				"grant_type":   {"authorization_code"},
				"redirect_uri": {"https://example.com/callback"},
			},
			capMapRules: []capRule{
				{
					Users:     []string{"*"},
					Resources: []string{"*"}, // Allow all resources
				},
			},
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var resp oidcTokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				// Decode JWT to check audience
				token, err := jwt.ParseSigned(resp.IDToken)
				if err != nil {
					t.Fatalf("failed to parse JWT: %v", err)
				}
				var claims map[string]interface{}
				if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
					t.Fatalf("failed to get claims: %v", err)
				}
				aud, ok := claims["aud"].([]interface{})
				if !ok {
					t.Fatalf("expected aud to be an array, got %T", claims["aud"])
				}
				if len(aud) != 3 {
					t.Errorf("expected 3 audience values, got %d", len(aud))
				}
			},
		},
		{
			name:               "token request with resource parameter",
			authorizationQuery: "client_id=test-client&redirect_uri=https://example.com/callback",
			tokenFormData: url.Values{
				"grant_type":   {"authorization_code"},
				"redirect_uri": {"https://example.com/callback"},
				"resource":     {"https://api.example.com"},
			},
			capMapRules: []capRule{
				{
					Users:     []string{"user@example.com"},
					Resources: []string{"https://api.example.com"},
				},
			},
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var resp oidcTokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp.AccessToken == "" {
					t.Error("expected access token")
				}
			},
		},
		{
			name:               "unauthorized resource request",
			authorizationQuery: "client_id=test-client&redirect_uri=https://example.com/callback",
			tokenFormData: url.Values{
				"grant_type":   {"authorization_code"},
				"redirect_uri": {"https://example.com/callback"},
				"resource":     {"https://unauthorized.example.com"},
			},
			capMapRules: []capRule{
				{
					Users:     []string{"user@example.com"},
					Resources: []string{"https://api.example.com"},
				},
			},
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IDPServer{
				serverURL:     "https://idp.test.ts.net",
				code:          make(map[string]*AuthRequest),
				accessToken:   make(map[string]*AuthRequest),
				refreshToken:  make(map[string]*AuthRequest),
				funnelClients: make(map[string]*FunnelClient),
			}

			// Parse authorization query
			authQuery, _ := url.ParseQuery(tt.authorizationQuery)

			// Create mock authRequest
			code := "test-code"
			ar := &AuthRequest{
				FunnelRP: &FunnelClient{
					ID:           "test-client",
					Secret:       "test-secret",
					RedirectURIs: []string{"https://example.com/callback"},
				},
				ClientID:    authQuery.Get("client_id"),
				RedirectURI: authQuery.Get("redirect_uri"),
				Resources:   authQuery["resource"],
				RemoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
						Key:  key.NodePublic{},
						Addresses: []netip.Prefix{
							netip.MustParsePrefix("100.64.0.1/32"),
						},
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName:   "user@example.com",
						DisplayName: "Test User",
					},
					CapMap: tailcfg.PeerCapMap{
						"tailscale.com/cap/tsidp": marshalCapRules(tt.capMapRules),
					},
				},
				ValidTill: time.Now().Add(5 * time.Minute),
			}

			s.funnelClients["test-client"] = ar.FunnelRP
			s.code[code] = ar

			// Add code to form data
			tt.tokenFormData.Set("code", code)
			tt.tokenFormData.Set("client_id", "test-client")
			tt.tokenFormData.Set("client_secret", "test-secret")

			req := httptest.NewRequest("POST", "/token", strings.NewReader(tt.tokenFormData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.checkResponse != nil && rr.Code == http.StatusOK {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}

// TestIntrospectTokenExpiration tests introspection of expired tokens
// Migrated from legacy/tsidp_test.go:2332-2375
func TestIntrospectTokenExpiration(t *testing.T) {
	s := &IDPServer{
		serverURL:     "https://idp.test.ts.net",
		accessToken:   make(map[string]*AuthRequest),
		funnelClients: make(map[string]*FunnelClient),
	}

	// Create an expired token
	expiredToken := "expired-token"
	s.accessToken[expiredToken] = &AuthRequest{
		ValidTill: time.Now().Add(-10 * time.Minute), // expired
		FunnelRP: &FunnelClient{
			ID:     "test-client",
			Secret: "test-secret",
		},
		ClientID: "test-client",
	}

	// Set up the funnel client
	s.funnelClients["test-client"] = &FunnelClient{
		ID:     "test-client",
		Secret: "test-secret",
	}

	form := url.Values{}
	form.Set("token", expiredToken)
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveIntrospect(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Check response shows token as inactive
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if active, ok := resp["active"].(bool); !ok || active {
		t.Error("expected active: false for expired token")
	}

	// Verify token was deleted
	if _, exists := s.accessToken[expiredToken]; exists {
		t.Error("expected expired token to be deleted")
	}
}

// TestIntrospectWithResources tests introspection with resources
// Migrated from legacy/tsidp_test.go:2377-2431
func TestIntrospectWithResources(t *testing.T) {
	s := &IDPServer{
		serverURL:     "https://idp.test.ts.net",
		accessToken:   make(map[string]*AuthRequest),
		funnelClients: make(map[string]*FunnelClient),
	}

	// Create a token with resources
	activeToken := "active-token-with-resources"
	s.accessToken[activeToken] = &AuthRequest{
		ValidTill: time.Now().Add(10 * time.Minute), // not expired
		FunnelRP: &FunnelClient{
			ID:     "test-client",
			Secret: "test-secret",
		},
		ClientID:  "test-client",
		Resources: []string{"https://api1.example.com", "https://api2.example.com"},
		Scopes:    []string{"openid", "email"}, // Add scopes for testing
		JTI:       "test-jti-12345",            // Add JTI for testing new claim
		RemoteUser: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				User: 12345,
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "user@example.com",
			},
		},
	}

	// Set up the funnel client
	s.funnelClients["test-client"] = &FunnelClient{
		ID:     "test-client",
		Secret: "test-secret",
	}

	form := url.Values{}
	form.Set("token", activeToken)
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveIntrospect(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Check response shows token as active with resources in audience
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if active, ok := resp["active"].(bool); !ok || !active {
		t.Error("expected active: true for valid token")
	}

	// Check that resources are included in audience
	if aud, ok := resp["aud"].([]interface{}); ok {
		expectedAudiences := []string{"test-client", "https://api1.example.com", "https://api2.example.com"}
		if len(aud) != len(expectedAudiences) {
			t.Errorf("expected %d audience values, got %d", len(expectedAudiences), len(aud))
		}
	} else {
		t.Error("expected aud claim to be an array")
	}
}

// TestIntrospectionRFC7662Compliance tests RFC 7662 compliance
func TestIntrospectionRFC7662Compliance(t *testing.T) {
	s := &IDPServer{
		serverURL:     "https://idp.test.ts.net",
		accessToken:   make(map[string]*AuthRequest),
		funnelClients: make(map[string]*FunnelClient),
	}

	// Create a token with all fields populated
	activeToken := "test-token-rfc-compliance"
	now := time.Now()
	s.accessToken[activeToken] = &AuthRequest{
		ValidTill:      now.Add(10 * time.Minute),
		IssuedAt:       now,
		NotValidBefore: now.Add(-NotValidBeforeClockSkew),
		FunnelRP: &FunnelClient{
			ID:     "test-client",
			Secret: "test-secret",
		},
		ClientID:  "test-client",
		Resources: []string{"https://api.example.com"},
		Scopes:    []string{"openid", "profile", "email"},
		JTI:       "unique-jwt-id-12345",
		RemoteUser: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				User: 12345,
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName:     "user@example.com",
				DisplayName:   "Test User",
				ProfilePicURL: "https://example.com/pic.jpg",
			},
		},
	}

	// Set up the funnel client
	s.funnelClients["test-client"] = &FunnelClient{
		ID:     "test-client",
		Secret: "test-secret",
	}

	form := url.Values{}
	form.Set("token", activeToken)
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveIntrospect(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Check all RFC 7662 required and recommended claims
	requiredClaims := map[string]bool{
		"active":             true,
		"client_id":          true,
		"exp":                true,
		"iat":                true,
		"nbf":                true, // NEW
		"sub":                true,
		"aud":                true,
		"iss":                true, // NEW
		"jti":                true, // NEW
		"username":           true, // NEW
		"token_type":         true,
		"scope":              true,
		"email":              true, // from scope
		"preferred_username": true, // from scope
		"picture":            true, // from scope
	}

	for claim, required := range requiredClaims {
		if _, ok := resp[claim]; !ok && required {
			t.Errorf("missing required claim: %s", claim)
		}
	}

	// Verify specific claim values
	if username, ok := resp["username"].(string); !ok || username != "user@example.com" {
		t.Errorf("expected username to be 'user@example.com', got: %v", resp["username"])
	}
	if iss, ok := resp["iss"].(string); !ok || iss != s.serverURL {
		t.Errorf("expected iss to be '%s', got: %v", s.serverURL, resp["iss"])
	}
	if jti, ok := resp["jti"].(string); !ok || jti != "unique-jwt-id-12345" {
		t.Errorf("expected jti to be 'unique-jwt-id-12345', got: %v", resp["jti"])
	}

	// Check that nbf is set and less than iat
	if nbf, ok := resp["nbf"].(float64); ok {
		if iat, ok := resp["iat"].(float64); ok {
			if nbf >= iat {
				t.Errorf("expected nbf to be less than iat, got nbf=%v, iat=%v", nbf, iat)
			}
		} else {
			t.Error("iat claim missing or wrong type")
		}
	} else {
		t.Error("nbf claim missing or wrong type")
	}
}

// TestRefreshTokenFlow tests refresh token grant flow
// Migrated from legacy/tsidp_test.go:1791-1940
func TestRefreshTokenFlow(t *testing.T) {
	tests := []struct {
		name          string
		grantType     string
		refreshToken  string
		clientID      string
		clientSecret  string
		expectStatus  int
		checkResponse func(t *testing.T, body []byte)
	}{
		{
			name:         "valid refresh token grant",
			grantType:    "refresh_token",
			refreshToken: "valid-refresh-token",
			clientID:     "test-client",
			clientSecret: "test-secret",
			expectStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var resp oidcTokenResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp.AccessToken == "" {
					t.Error("expected access token")
				}
				if resp.RefreshToken == "" {
					t.Error("expected new refresh token")
				}
				if resp.IDToken == "" {
					t.Error("expected ID token")
				}
				if resp.TokenType != "Bearer" {
					t.Errorf("expected token type Bearer, got %s", resp.TokenType)
				}
				if resp.ExpiresIn != 300 {
					t.Errorf("expected expires_in 300, got %d", resp.ExpiresIn)
				}
			},
		},
		{
			name:         "missing refresh token",
			grantType:    "refresh_token",
			refreshToken: "",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_request" {
					t.Errorf("expected error code 'invalid_request', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "refresh_token is required") {
					t.Errorf("expected error description about refresh_token, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "invalid refresh token",
			grantType:    "refresh_token",
			refreshToken: "invalid-token",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_grant" {
					t.Errorf("expected error code 'invalid_grant', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "invalid refresh token") {
					t.Errorf("expected error description about invalid refresh token, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "expired refresh token",
			grantType:    "refresh_token",
			refreshToken: "expired-token",
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_grant" {
					t.Errorf("expected error code 'invalid_grant', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "invalid refresh token") {
					t.Errorf("expected error description about invalid refresh token, got: %v", errResp["error_description"])
				}
			},
		},
		// This test case validates that the server implementation properly validates
		// client credentials in refresh token flow the same way as legacy implementation.
		// Both legacy and server should reject with 401/invalid_client.
		// SECURITY FIX: Previously server incorrectly allowed this, now it properly rejects.
		{
			name:         "wrong client credentials - now properly rejected",
			grantType:    "refresh_token",
			refreshToken: "valid-refresh-token",
			clientID:     "wrong-client",
			clientSecret: "wrong-secret",
			expectStatus: http.StatusBadRequest, // Both legacy and server should reject this
			checkResponse: func(t *testing.T, body []byte) {
				var resp httpErrorResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				// Both legacy and server should reject with invalid_client error
				if resp.Error != "invalid_client" {
					t.Errorf("expected error 'invalid_client', got: %v", resp.Error)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IDPServer{
				serverURL:     "https://idp.test.ts.net",
				refreshToken:  make(map[string]*AuthRequest),
				funnelClients: make(map[string]*FunnelClient),
			}

			// Set up test data
			if tt.refreshToken == "valid-refresh-token" {
				s.refreshToken[tt.refreshToken] = &AuthRequest{
					FunnelRP: &FunnelClient{
						ID:     "test-client",
						Secret: "test-secret",
					},
					ClientID:  "test-client",
					Scopes:    []string{"openid", "email"}, // Add scopes to refresh token
					ValidTill: time.Now().Add(time.Hour),
					RemoteUser: &apitype.WhoIsResponse{
						Node: &tailcfg.Node{
							ID:        1,
							Name:      "node1.example.ts.net",
							User:      tailcfg.UserID(1),
							Key:       key.NodePublic{},
							Addresses: []netip.Prefix{},
						},
						UserProfile: &tailcfg.UserProfile{
							LoginName:     "user@example.com",
							DisplayName:   "Test User",
							ProfilePicURL: "https://example.com/pic.jpg",
						},
					},
				}
				// Always set up the correct client for this refresh token
				s.funnelClients["test-client"] = &FunnelClient{
					ID:     "test-client",
					Secret: "test-secret",
				}

				// Don't set up the wrong client - it should be rejected as unknown
			} else if tt.refreshToken == "expired-token" {
				s.refreshToken[tt.refreshToken] = &AuthRequest{
					FunnelRP: &FunnelClient{
						ID:     "test-client",
						Secret: "test-secret",
					},
					ClientID:  "test-client",
					ValidTill: time.Now().Add(-time.Hour), // expired
				}
			}

			// Create request
			form := url.Values{}
			form.Set("grant_type", tt.grantType)
			if tt.refreshToken != "" {
				form.Set("refresh_token", tt.refreshToken)
			}
			if tt.clientID != "" {
				form.Set("client_id", tt.clientID)
			}
			if tt.clientSecret != "" {
				form.Set("client_secret", tt.clientSecret)
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}

// TestTokenEndpointUnsupportedGrantType tests unsupported grant type handling
// Migrated from legacy/tsidp_test.go:1942-2003
func TestTokenEndpointUnsupportedGrantType(t *testing.T) {
	tests := []struct {
		name         string
		grantType    string
		expectStatus int
	}{
		{
			name:         "password grant type",
			grantType:    "password",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "client_credentials grant type",
			grantType:    "client_credentials",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "implicit grant type",
			grantType:    "implicit",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "unknown grant type",
			grantType:    "unknown_grant",
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IDPServer{
				serverURL: "https://idp.test.ts.net",
			}

			form := url.Values{
				"grant_type": {tt.grantType},
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			// Check JSON error response per RFC 6749
			var errResp map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("expected JSON error response, got: %s", rr.Body.String())
			}
			if errResp["error"] != "unsupported_grant_type" {
				t.Errorf("expected error code 'unsupported_grant_type', got: %v", errResp["error"])
			}

			// Check required headers per RFC 6749 Section 5.2
			if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Errorf("expected Content-Type application/json, got: %s", ct)
			}
		})
	}
}

// TestTokenExpiration tests token expiration handling
// Migrated from legacy/tsidp_test.go:2005-2069
func TestTokenExpiration(t *testing.T) {
	tests := []struct {
		name         string
		tokenAge     time.Duration
		expectStatus int
		expectError  string
	}{
		{
			name:         "valid access token",
			tokenAge:     -1 * time.Minute, // 1 minute old (still valid)
			expectStatus: http.StatusOK,
		},
		{
			name:         "expired access token",
			tokenAge:     10 * time.Minute,        // 10 minutes old (expired)
			expectStatus: http.StatusUnauthorized, // 401 per RFC 6750
			expectError:  "token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IDPServer{
				serverURL:   "https://idp.test.ts.net",
				accessToken: make(map[string]*AuthRequest),
			}

			// Create a test token
			testToken := "test-access-token"
			s.accessToken[testToken] = &AuthRequest{
				ValidTill: time.Now().Add(-tt.tokenAge),
				RemoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName:   "user@example.com",
						DisplayName: "Test User",
					},
				},
			}

			req := httptest.NewRequest("GET", "/userinfo", nil)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)

			rr := httptest.NewRecorder()
			s.serveUserInfo(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d", tt.expectStatus, rr.Code)
			}

			if tt.expectError != "" {
				// Check for WWW-Authenticate header as per RFC 6750
				authHeader := rr.Header().Get("WWW-Authenticate")
				if authHeader == "" {
					t.Error("expected WWW-Authenticate header for Bearer token error")
				}
				if !strings.Contains(authHeader, `error="invalid_token"`) {
					t.Errorf("expected WWW-Authenticate header with invalid_token error, got: %s", authHeader)
				}
				if !strings.Contains(authHeader, tt.expectError) {
					t.Errorf("expected error description containing %q in WWW-Authenticate header, got: %s", tt.expectError, authHeader)
				}
				// Verify token was deleted
				if _, exists := s.accessToken[testToken]; exists {
					t.Error("expected expired token to be deleted")
				}
			}
		})
	}
}

// TestRefreshTokenWithResources tests refresh tokens with resource downscoping (RFC 8707)
// Migrated from legacy/tsidp_test.go:1076-1187
func TestRefreshTokenWithResources(t *testing.T) {
	tests := []struct {
		name              string
		originalResources []string
		refreshResources  []string
		capMapRules       []capRule
		expectStatus      int
		expectError       string
	}{
		{
			name:              "refresh with resource downscoping",
			originalResources: []string{"https://api1.example.com", "https://api2.example.com"},
			refreshResources:  []string{"https://api1.example.com"},
			capMapRules: []capRule{
				{
					Users:     []string{"*"},
					Resources: []string{"*"},
				},
			},
			expectStatus: http.StatusOK,
		},
		{
			name:              "refresh with resource not in original grant",
			originalResources: []string{"https://api1.example.com"},
			refreshResources:  []string{"https://api2.example.com"},
			capMapRules: []capRule{
				{
					Users:     []string{"*"},
					Resources: []string{"*"},
				},
			},
			expectStatus: http.StatusBadRequest,
			expectError:  "requested resource not in original grant",
		},
		{
			name:              "refresh without resource parameter",
			originalResources: []string{"https://api1.example.com"},
			refreshResources:  nil,
			capMapRules: []capRule{
				{
					Users:     []string{"*"},
					Resources: []string{"*"},
				},
			},
			expectStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(nil, "", false, false, false)

			// Create refresh token
			rt := "test-refresh-token"
			ar := &AuthRequest{
				FunnelRP: &FunnelClient{
					ID:     "test-client",
					Secret: "test-secret",
				},
				ClientID:  "test-client",
				Resources: tt.originalResources,
				ValidTill: time.Now().Add(time.Hour),
				RemoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
						Key:  key.NodePublic{},
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName:   "user@example.com",
						DisplayName: "Test User",
					},
					CapMap: tailcfg.PeerCapMap{
						"tailscale.com/cap/tsidp": marshalCapRules(tt.capMapRules),
					},
				},
			}
			s.refreshToken[rt] = ar
			s.funnelClients["test-client"] = ar.FunnelRP

			// Create request
			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {rt},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			}
			for _, res := range tt.refreshResources {
				form.Add("resource", res)
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.expectError != "" && !strings.Contains(rr.Body.String(), tt.expectError) {
				t.Errorf("expected error containing %q, got %q", tt.expectError, rr.Body.String())
			}
		})
	}
}

// TestRefreshTokenScopePreservation tests scope preservation in refresh tokens
// Migrated from legacy/tsidp_test.go:1460-1541
func TestRefreshTokenScopePreservation(t *testing.T) {
	s := New(nil, "", false, false, false)

	// Create refresh token with specific scopes
	rt := "test-refresh-token-scopes"
	originalScopes := []string{"openid", "profile"}
	s.refreshToken[rt] = &AuthRequest{
		FunnelRP: &FunnelClient{
			ID:     "test-client",
			Secret: "test-secret",
		},
		ClientID:  "test-client",
		Scopes:    originalScopes,
		ValidTill: time.Now().Add(time.Hour),
		RemoteUser: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				ID:   1,
				Name: "node1.example.ts.net",
				User: tailcfg.UserID(1),
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName:   "user@example.com",
				DisplayName: "Test User",
			},
		},
	}
	s.funnelClients["test-client"] = &FunnelClient{
		ID:     "test-client",
		Secret: "test-secret",
	}

	// Issue new tokens using refresh token
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Parse response to get new access token
	var tokenResp oidcTokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("failed to unmarshal token response: %v", err)
	}

	// Verify the new access token has the same scopes
	if newAR, ok := s.accessToken[tokenResp.AccessToken]; ok {
		if len(newAR.Scopes) != len(originalScopes) {
			t.Errorf("new access token has %d scopes, expected %d", len(newAR.Scopes), len(originalScopes))
		}
		for i, scope := range newAR.Scopes {
			if i < len(originalScopes) && scope != originalScopes[i] {
				t.Errorf("scope[%d] = %q, expected %q", i, scope, originalScopes[i])
			}
		}
	} else {
		t.Error("new access token not found in server state")
	}

	// Verify the new refresh token also has the same scopes
	if newRT, ok := s.refreshToken[tokenResp.RefreshToken]; ok {
		if len(newRT.Scopes) != len(originalScopes) {
			t.Errorf("new refresh token has %d scopes, expected %d", len(newRT.Scopes), len(originalScopes))
		}
	} else {
		t.Error("new refresh token not found in server state")
	}
}

// TestAZPClaimWithMultipleAudiences tests azp claim handling with multiple audiences
// Migrated from legacy/tsidp_test.go:1543-1679
func TestAZPClaimWithMultipleAudiences(t *testing.T) {
	tests := []struct {
		name              string
		resources         []string
		expectAZP         bool
		expectedAudiences int
	}{
		{
			name:              "single audience - no azp",
			resources:         []string{},
			expectAZP:         false,
			expectedAudiences: 1, // just client_id
		},
		{
			name:              "multiple audiences - azp required",
			resources:         []string{"https://api1.example.com", "https://api2.example.com"},
			expectAZP:         true,
			expectedAudiences: 3, // client_id + 2 resources
		},
		{
			name:              "single resource - azp required",
			resources:         []string{"https://api.example.com"},
			expectAZP:         true,
			expectedAudiences: 2, // client_id + 1 resource
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(nil, "", false, false, false)

			// Set up funnel client
			s.funnelClients["test-client"] = &FunnelClient{
				ID:           "test-client",
				Secret:       "test-secret",
				RedirectURIs: []string{"https://example.com/callback"},
			}

			// Create auth request
			code := "test-code"
			ar := &AuthRequest{
				FunnelRP:    s.funnelClients["test-client"],
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
				Resources:   tt.resources,
				Scopes:      []string{"openid"},
				RemoteUser: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   1,
						Name: "node1.example.ts.net",
						User: tailcfg.UserID(1),
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName: "user@example.com",
					},
				},
				ValidTill: time.Now().Add(5 * time.Minute),
			}
			s.code[code] = ar

			// Exchange code for token
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {"https://example.com/callback"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
			}

			var tokenResp oidcTokenResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Parse the ID token
			token, err := jwt.ParseSigned(tokenResp.IDToken)
			if err != nil {
				t.Fatalf("failed to parse JWT: %v", err)
			}

			var claims map[string]interface{}
			if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
				t.Fatalf("failed to get claims: %v", err)
			}

			// Check audience
			aud, ok := claims["aud"]
			if !ok {
				t.Fatal("aud claim not found")
			}

			// The JWT library always serializes audience as an array
			audArray, isArray := aud.([]interface{})
			if !isArray {
				t.Errorf("expected audience to be array, got %T", aud)
			}

			if len(audArray) != tt.expectedAudiences {
				t.Errorf("expected %d audiences, got %d", tt.expectedAudiences, len(audArray))
			}

			// Check azp claim
			azp, hasAZP := claims["azp"]
			if tt.expectAZP && !hasAZP {
				t.Error("expected azp claim for multiple audiences, but not found")
			}
			if !tt.expectAZP && hasAZP {
				t.Error("unexpected azp claim for single audience")
			}
			if hasAZP {
				azpStr, ok := azp.(string)
				if !ok {
					t.Errorf("azp claim should be string, got %T", azp)
				}
				if azpStr != "test-client" {
					t.Errorf("expected azp to be 'test-client', got %s", azpStr)
				}
			}
		})
	}
}

// Ported from:
// https://github.com/tailscale/tailscale/blob/3e4b0c1516819ea47a90189a4f116a2e44b97e39/cmd/tsidp/tsidp_test.go#L484
// - core test logic unchanged
// - renamed idpServer -> IDPServer
// - renamed authRequest -> AuthRequest
func TestServeToken(t *testing.T) {
	tests := []struct {
		name           string
		caps           tailcfg.PeerCapMap
		method         string
		grantType      string
		code           string
		omitCode       bool
		redirectURI    string
		remoteAddr     string
		expectError    bool
		expected       map[string]any
		clientID       string
		clientSecret   string
		useCredentials bool
	}{
		{
			name:        "GET not allowed",
			method:      "GET",
			grantType:   "authorization_code",
			expectError: true,
		},
		{
			name:        "unsupported grant type",
			method:      "POST",
			grantType:   "pkcs",
			expectError: true,
		},
		{
			name:        "invalid code",
			method:      "POST",
			grantType:   "authorization_code",
			code:        "invalid-code",
			expectError: true,
		},
		{
			name:        "omit code from form",
			method:      "POST",
			grantType:   "authorization_code",
			omitCode:    true,
			expectError: true,
		},
		{
			name:        "invalid redirect uri",
			method:      "POST",
			grantType:   "authorization_code",
			code:        "valid-code",
			redirectURI: "https://invalid.example.com/callback",
			remoteAddr:  "127.0.0.1:12345",
			expectError: true,
		},
		{
			name:        "invalid remoteAddr",
			method:      "POST",
			grantType:   "authorization_code",
			redirectURI: "https://rp.example.com/callback",
			code:        "valid-code",
			remoteAddr:  "192.168.0.1:12345",
			expectError: true,
		},
		{
			name:           "extra claim included",
			method:         "POST",
			grantType:      "authorization_code",
			redirectURI:    "https://rp.example.com/callback",
			code:           "extra-claim-included",
			remoteAddr:     "127.0.0.1:12345",
			clientID:       "test-client",
			clientSecret:   "test-secret",
			useCredentials: true,
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]any{
							"foo": "bar",
						},
					}),
				},
			},
			expected: map[string]any{
				"foo": "bar",
			},
		},
		{
			name:        "attempt to overwrite protected claim",
			method:      "POST",
			grantType:   "authorization_code",
			redirectURI: "https://rp.example.com/callback",
			code:        "valid-code",
			caps: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTsIDP: {
					mustMarshalJSON(t, capRule{
						IncludeInUserInfo: true,
						ExtraClaims: map[string]any{
							"sub": "should-not-overwrite",
						},
					}),
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()

			// Fake user/node
			profile := &tailcfg.UserProfile{
				LoginName:     "alice@example.com",
				DisplayName:   "Alice Example",
				ProfilePicURL: "https://example.com/alice.jpg",
			}
			node := &tailcfg.Node{
				ID:       123,
				Name:     "test-node.test.ts.net.",
				User:     456,
				Key:      key.NodePublic{},
				Cap:      1,
				DiscoKey: key.DiscoPublic{},
			}

			remoteUser := &apitype.WhoIsResponse{
				Node:        node,
				UserProfile: profile,
				CapMap:      tt.caps,
			}

			s := &IDPServer{
				code: map[string]*AuthRequest{
					"valid-code": {
						ClientID:    "test-client",
						Nonce:       "nonce123",
						RedirectURI: "https://rp.example.com/callback",
						ValidTill:   now.Add(5 * time.Minute),
						RemoteUser:  remoteUser,
					},

					// only for the extra claim included test
					// which requires checking a client_id and client_secret
					"extra-claim-included": {
						ClientID:    "test-client",
						Nonce:       "nonce123",
						RedirectURI: "https://rp.example.com/callback",
						ValidTill:   now.Add(5 * time.Minute),
						RemoteUser:  remoteUser,
						FunnelRP: &FunnelClient{
							Name:         "A Test Client",
							ID:           "test-client",
							Secret:       "test-secret",
							RedirectURIs: []string{"https://rp.example.com"},
						},
					},
				},
			}
			// Inject a working signer
			s.lazySigner.Set(oidcTestingSigner(t))

			form := url.Values{}
			form.Set("grant_type", tt.grantType)
			form.Set("redirect_uri", tt.redirectURI)
			if !tt.omitCode {
				form.Set("code", tt.code)
			}

			if tt.useCredentials {
				t.Log("Sending credentials") // Debug log"
				form.Set("client_id", tt.clientID)
				form.Set("client_secret", tt.clientSecret)
			}

			req := httptest.NewRequest(tt.method, "/token", strings.NewReader(form.Encode()))
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			s.serveToken(rr, req)

			if tt.expectError {
				if rr.Code == http.StatusOK {
					t.Fatalf("expected error, got 200 OK: %s", rr.Body.String())
				}
				return
			}

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
			}

			var resp struct {
				IDToken string `json:"id_token"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			tok, err := jwt.ParseSigned(resp.IDToken)
			if err != nil {
				t.Fatalf("failed to parse ID token: %v", err)
			}

			out := make(map[string]any)
			if err := tok.Claims(oidcTestingPublicKey(t), &out); err != nil {
				t.Fatalf("failed to extract claims: %v", err)
			}

			for k, want := range tt.expected {
				got, ok := out[k]
				if !ok {
					t.Errorf("missing expected claim %q", k)
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("claim %q: got %v, want %v", k, got, want)
				}
			}
		})
	}
}

// TestServeTokenWithClientValidation verifies OAuth token endpoint security
func TestServeTokenWithClientValidation(t *testing.T) {
	tests := []struct {
		name                string
		method              string
		grantType           string
		code                string
		clientID            string
		clientSecret        string
		redirectURI         string
		useBasicAuth        bool
		setupAuthRequest    bool
		authRequestClient   string
		authRequestRedirect string
		expectError         bool
		expectCode          int
		expectIDToken       bool
	}{
		{
			name:                "valid token exchange with form credentials",
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			clientID:            "test-client",
			clientSecret:        "test-secret",
			redirectURI:         "https://rp.example.com/callback",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectIDToken:       true,
		},
		{
			name:                "valid token exchange with basic auth",
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			redirectURI:         "https://rp.example.com/callback",
			useBasicAuth:        true,
			clientID:            "test-client",
			clientSecret:        "test-secret",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectIDToken:       true,
		},
		{
			name:                "missing client credentials",
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			redirectURI:         "https://rp.example.com/callback",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectError:         true,
			expectCode:          http.StatusUnauthorized,
		},
		{
			name:              "client_id mismatch",
			method:            "POST",
			grantType:         "authorization_code",
			code:              "valid-code",
			clientID:          "wrong-client",
			clientSecret:      "test-secret",
			redirectURI:       "https://rp.example.com/callback",
			setupAuthRequest:  true,
			authRequestClient: "test-client",
			expectError:       true,
			expectCode:        http.StatusBadRequest,
		},
		{
			name:                "invalid client secret",
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			clientID:            "test-client",
			clientSecret:        "wrong-secret",
			redirectURI:         "https://rp.example.com/callback",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectError:         true,
			expectCode:          http.StatusUnauthorized,
		},
		{
			name:                "redirect_uri mismatch",
			method:              "POST",
			grantType:           "authorization_code",
			code:                "valid-code",
			clientID:            "test-client",
			clientSecret:        "test-secret",
			redirectURI:         "https://wrong.example.com/callback",
			setupAuthRequest:    true,
			authRequestClient:   "test-client",
			authRequestRedirect: "https://rp.example.com/callback",
			expectError:         true,
			expectCode:          http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := setupTestServer(t, nil)

			// Setup authorization request if needed
			if tt.setupAuthRequest {
				now := time.Now()
				profile := &tailcfg.UserProfile{
					LoginName:     "alice@example.com",
					DisplayName:   "Alice Example",
					ProfilePicURL: "https://example.com/alice.jpg",
				}
				node := &tailcfg.Node{
					ID:       123,
					Name:     "test-node.test.ts.net.",
					User:     456,
					Key:      key.NodePublic{},
					Cap:      1,
					DiscoKey: key.DiscoPublic{},
				}
				remoteUser := &apitype.WhoIsResponse{
					Node:        node,
					UserProfile: profile,
					CapMap:      tailcfg.PeerCapMap{},
				}

				var funnelClientPtr *FunnelClient
				if tt.authRequestClient != "" {
					funnelClientPtr = &FunnelClient{
						ID:          tt.authRequestClient,
						Secret:      "test-secret",
						Name:        "Test Client",
						RedirectURI: tt.authRequestRedirect,
					}
					srv.funnelClients[tt.authRequestClient] = funnelClientPtr
				}

				srv.code["valid-code"] = &AuthRequest{
					ClientID:    tt.authRequestClient,
					Nonce:       "nonce123",
					RedirectURI: tt.authRequestRedirect,
					ValidTill:   now.Add(5 * time.Minute),
					RemoteUser:  remoteUser,
					FunnelRP:    funnelClientPtr,
				}
			}

			// Create form data
			form := url.Values{}
			form.Set("grant_type", tt.grantType)
			form.Set("code", tt.code)
			form.Set("redirect_uri", tt.redirectURI)

			if !tt.useBasicAuth {
				if tt.clientID != "" {
					form.Set("client_id", tt.clientID)
				}
				if tt.clientSecret != "" {
					form.Set("client_secret", tt.clientSecret)
				}
			}

			req := httptest.NewRequest(tt.method, "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "127.0.0.1:12345"

			if tt.useBasicAuth && tt.clientID != "" && tt.clientSecret != "" {
				req.SetBasicAuth(tt.clientID, tt.clientSecret)
			}

			rr := httptest.NewRecorder()
			srv.serveToken(rr, req)

			if tt.expectError {
				if rr.Code != tt.expectCode {
					t.Errorf("expected status code %d, got %d: %s", tt.expectCode, rr.Code, rr.Body.String())
				}
			} else if tt.expectIDToken {
				if rr.Code != http.StatusOK {
					t.Errorf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
				}

				var resp struct {
					IDToken     string `json:"id_token"`
					AccessToken string `json:"access_token"`
					TokenType   string `json:"token_type"`
					ExpiresIn   int    `json:"expires_in"`
				}

				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				if resp.IDToken == "" {
					t.Error("expected id_token in response")
				}
				if resp.AccessToken == "" {
					t.Error("expected access_token in response")
				}
				if resp.TokenType != "Bearer" {
					t.Errorf("expected token_type 'Bearer', got '%s'", resp.TokenType)
				}
				if resp.ExpiresIn != 300 {
					t.Errorf("expected expires_in 300, got %d", resp.ExpiresIn)
				}

				// Verify access token was stored
				srv.mu.Lock()
				_, ok := srv.accessToken[resp.AccessToken]
				srv.mu.Unlock()

				if !ok {
					t.Error("expected access token to be stored")
				}

				// Verify authorization code was consumed
				srv.mu.Lock()
				_, ok = srv.code[tt.code]
				srv.mu.Unlock()

				if ok {
					t.Error("expected authorization code to be consumed")
				}
			}
		})
	}
}
