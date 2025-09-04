// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
		capMapRules        []stsCapRule
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
			capMapRules: []stsCapRule{
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
			capMapRules: []stsCapRule{
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
			capMapRules: []stsCapRule{
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
			capMapRules: []stsCapRule{
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
						"test-tailscale.com/idp/sts/openly-allow": marshalCapRules(tt.capMapRules),
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
// Migrated from legacy/tsidp_test.go:2433-2512
func TestIntrospectionRFC7662Compliance(t *testing.T) {
	s := &IDPServer{
		serverURL:     "https://idp.test.ts.net",
		loopbackURL:   "http://localhost:8080",
		accessToken:   make(map[string]*AuthRequest),
		funnelClients: make(map[string]*FunnelClient),
	}

	// Create a token with all fields populated
	activeToken := "test-token-rfc-compliance"
	s.accessToken[activeToken] = &AuthRequest{
		ValidTill: time.Now().Add(10 * time.Minute),
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

	// Check that nbf is set and equals iat
	if nbf, ok := resp["nbf"].(float64); ok {
		if iat, ok := resp["iat"].(float64); ok {
			if nbf != iat {
				t.Errorf("expected nbf to equal iat, got nbf=%v, iat=%v", nbf, iat)
			}
		}
	} else {
		t.Error("nbf claim missing or wrong type")
	}
}

// marshalCapRules is a helper to convert stsCapRule slice to JSON for testing
// Migrated from legacy/tsidp_test.go:2653-2661
func marshalCapRules(rules []stsCapRule) []tailcfg.RawMessage {
	// UnmarshalCapJSON expects each rule to be a separate RawMessage
	var msgs []tailcfg.RawMessage
	for _, rule := range rules {
		data, _ := json.Marshal(rule)
		msgs = append(msgs, tailcfg.RawMessage(data))
	}
	return msgs
}