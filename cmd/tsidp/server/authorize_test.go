// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// TestScopeHandling tests OAuth scope validation and handling
// Migrated from legacy/tsidp_test.go:2027-2167
func TestScopeHandling(t *testing.T) {
	tests := []struct {
		name            string
		authQuery       string
		expectedScopes  []string
		expectAuthError bool
	}{
		{
			name:           "single valid scope",
			authQuery:      "client_id=test-client&redirect_uri=https://example.com/callback&scope=openid",
			expectedScopes: []string{"openid"},
		},
		{
			name:           "multiple valid scopes",
			authQuery:      "client_id=test-client&redirect_uri=https://example.com/callback&scope=openid email profile",
			expectedScopes: []string{"openid", "email", "profile"},
		},
		{
			name:           "no scope defaults to openid",
			authQuery:      "client_id=test-client&redirect_uri=https://example.com/callback",
			expectedScopes: []string{"openid"},
		},
		{
			name:            "invalid scope",
			authQuery:       "client_id=test-client&redirect_uri=https://example.com/callback&scope=openid invalid_scope",
			expectAuthError: true,
		},
		{
			name:           "extra spaces in scope",
			authQuery:      "client_id=test-client&redirect_uri=https://example.com/callback&scope=openid    email   profile",
			expectedScopes: []string{"openid", "email", "profile"},
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

			// Set up funnel client
			s.funnelClients["test-client"] = &FunnelClient{
				ID:           "test-client",
				Secret:       "test-secret",
				RedirectURIs: []string{"https://example.com/callback"},
			}

			// Parse query
			authValues, _ := url.ParseQuery(tt.authQuery)

			// Create mock AuthRequest
			code := "test-code"
			ar := &AuthRequest{
				ClientID:    authValues.Get("client_id"),
				RedirectURI: authValues.Get("redirect_uri"),
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
				ValidTill: time.Now().Add(5 * time.Minute),
			}

			// Parse and validate scopes
			if scopeParam := authValues.Get("scope"); scopeParam != "" {
				ar.Scopes = strings.Fields(scopeParam)
			}
			validatedScopes, err := s.validateScopes(ar.Scopes)

			if tt.expectAuthError {
				if err == nil {
					t.Error("expected scope validation error")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected scope validation error: %v", err)
				return
			}

			ar.Scopes = validatedScopes
			s.code[code] = ar

			// Verify scopes match expected
			if len(ar.Scopes) != len(tt.expectedScopes) {
				t.Errorf("expected %d scopes, got %d", len(tt.expectedScopes), len(ar.Scopes))
			}
			for i, scope := range ar.Scopes {
				if i < len(tt.expectedScopes) && scope != tt.expectedScopes[i] {
					t.Errorf("expected scope[%d] = %q, got %q", i, tt.expectedScopes[i], scope)
				}
			}

			// Test token endpoint preserves scopes
			if !tt.expectAuthError {
				form := url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {code},
					"redirect_uri":  {ar.RedirectURI},
					"client_id":     {"test-client"},
					"client_secret": {"test-secret"},
				}

				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				rr := httptest.NewRecorder()
				s.serveToken(rr, req)

				if rr.Code != http.StatusOK {
					t.Errorf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
				}

				// Verify the issued access token has the correct scopes
				var tokenResp struct {
					AccessToken string `json:"access_token"`
					TokenType   string `json:"token_type"`
					ExpiresIn   int    `json:"expires_in"`
					Scope       string `json:"scope"`
				}
				if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
					t.Fatalf("failed to unmarshal token response: %v", err)
				}

				if tokenAR, ok := s.accessToken[tokenResp.AccessToken]; ok {
					if len(tokenAR.Scopes) != len(tt.expectedScopes) {
						t.Errorf("access token has %d scopes, expected %d", len(tokenAR.Scopes), len(tt.expectedScopes))
					}
					for i, scope := range tokenAR.Scopes {
						if i < len(tt.expectedScopes) && scope != tt.expectedScopes[i] {
							t.Errorf("access token scope[%d] = %q, expected %q", i, scope, tt.expectedScopes[i])
						}
					}
				} else {
					t.Error("access token not found in server state")
				}
			}
		})
	}
}

// TestValidateScopes tests the validateScopes function directly
// This provides more focused unit testing of scope validation logic
func TestValidateScopes(t *testing.T) {
	s := &IDPServer{}

	tests := []struct {
		name           string
		inputScopes    []string
		expectedScopes []string
		expectError    bool
	}{
		{
			name:           "empty scopes default to openid",
			inputScopes:    nil,
			expectedScopes: []string{"openid"},
			expectError:    false,
		},
		{
			name:           "single valid scope",
			inputScopes:    []string{"openid"},
			expectedScopes: []string{"openid"},
			expectError:    false,
		},
		{
			name:           "multiple valid scopes",
			inputScopes:    []string{"openid", "email", "profile"},
			expectedScopes: []string{"openid", "email", "profile"},
			expectError:    false,
		},
		{
			name:        "invalid scope",
			inputScopes: []string{"openid", "invalid_scope"},
			expectError: true,
		},
		{
			name:           "duplicate scopes",
			inputScopes:    []string{"openid", "email", "openid"},
			expectedScopes: []string{"openid", "email", "openid"},
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.validateScopes(tt.inputScopes)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(result) != len(tt.expectedScopes) {
				t.Errorf("expected %d scopes, got %d", len(tt.expectedScopes), len(result))
			}

			for i, scope := range result {
				if i < len(tt.expectedScopes) && scope != tt.expectedScopes[i] {
					t.Errorf("expected scope[%d] = %q, got %q", i, tt.expectedScopes[i], scope)
				}
			}
		})
	}
}