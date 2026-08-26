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

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// TestScopeHandling tests OAuth scope validation and handling
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
				FunnelRP:    s.funnelClients["test-client"], // Set funnel client for authentication
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

// TestPKCE tests PKCE (Proof Key for Code Exchange) implementation (RFC 7636)
func TestPKCE(t *testing.T) {
	tests := []struct {
		name             string
		authQuery        string
		codeVerifier     string
		expectAuthError  bool
		expectTokenError bool
		checkResponse    func(t *testing.T, body []byte)
	}{
		{
			name:         "valid PKCE with S256 method",
			authQuery:    "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			// code_challenge = BASE64URL(SHA256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
			// = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		},
		{
			name:         "valid PKCE with plain method",
			authQuery:    "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=plain",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:         "PKCE with default plain method",
			authQuery:    "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:             "missing code_verifier",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
			codeVerifier:     "",
			expectTokenError: true,
		},
		{
			name:             "invalid code_verifier",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
			codeVerifier:     "wrong-verifier-that-does-not-match-the-challenge",
			expectTokenError: true,
		},
		{
			name:            "unsupported code_challenge_method",
			authQuery:       "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=test&code_challenge_method=invalid",
			expectAuthError: true,
		},
		{
			name:             "code_verifier too short",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=short&code_challenge_method=plain",
			codeVerifier:     "short", // less than 43 characters
			expectTokenError: true,
		},
		{
			name:             "code_verifier too long",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=" + strings.Repeat("a", 129) + "&code_challenge_method=plain",
			codeVerifier:     strings.Repeat("a", 129), // more than 128 characters
			expectTokenError: true,
		},
		{
			name:             "code_verifier with invalid characters",
			authQuery:        "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!&code_challenge_method=plain",
			codeVerifier:     "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!", // contains '!' which is invalid
			expectTokenError: true,
		},
		{
			name:         "no PKCE parameters - backward compatibility",
			authQuery:    "client_id=test-client&redirect_uri=https://example.com/callback",
			codeVerifier: "", // no code_verifier sent
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

			// Parse authorization query
			authValues, _ := url.ParseQuery(tt.authQuery)

			// Create mock AuthRequest based on authorization
			code := "test-code"
			ar := &AuthRequest{
				ClientID:    authValues.Get("client_id"),
				RedirectURI: authValues.Get("redirect_uri"),
				FunnelRP:    s.funnelClients["test-client"], // Set funnel client for authentication
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
				Scopes:    []string{"openid"},
			}

			// Handle PKCE parameters from authorization
			if codeChallenge := authValues.Get("code_challenge"); codeChallenge != "" {
				ar.CodeChallenge = codeChallenge
				ar.CodeChallengeMethod = authValues.Get("code_challenge_method")
				if ar.CodeChallengeMethod == "" {
					ar.CodeChallengeMethod = "plain"
				}
			}

			// Check for auth errors first (unsupported method)
			if tt.expectAuthError {
				if ar.CodeChallengeMethod != "" && ar.CodeChallengeMethod != "plain" && ar.CodeChallengeMethod != "S256" {
					// Expected error - unsupported method
					return
				}
			}

			s.code[code] = ar

			// Now test token exchange
			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {ar.RedirectURI},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			}
			if tt.codeVerifier != "" {
				form.Set("code_verifier", tt.codeVerifier)
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.serveToken(rr, req)

			if tt.expectTokenError {
				if rr.Code == http.StatusOK {
					t.Errorf("expected token error, got status 200")
				}
			} else {
				if rr.Code != http.StatusOK {
					t.Errorf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
				}
			}

			if tt.checkResponse != nil && rr.Code == http.StatusOK {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}

// TestPKCEWithRefreshToken tests PKCE with refresh token flow
func TestPKCEWithRefreshToken(t *testing.T) {
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

	// Step 1: Initial authorization with PKCE
	code := "test-code"
	ar := &AuthRequest{
		ClientID:            "test-client",
		RedirectURI:         "https://example.com/callback",
		FunnelRP:            s.funnelClients["test-client"], // Set funnel client for authentication
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid", "offline_access"},
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
	s.code[code] = ar

	// Step 2: Exchange code for tokens with code_verifier
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://example.com/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.serveToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Parse initial token response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("failed to unmarshal token response: %v", err)
	}

	if tokenResp.RefreshToken == "" {
		t.Fatal("expected refresh token to be present")
	}

	// Step 3: Use refresh token to get new access token
	// Note: PKCE should not be required for refresh token flow
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenResp.RefreshToken},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		// Deliberately omit code_verifier - should not be needed for refresh
	}

	refreshReq := httptest.NewRequest("POST", "/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	refreshRr := httptest.NewRecorder()
	s.serveToken(refreshRr, refreshReq)

	if refreshRr.Code != http.StatusOK {
		t.Errorf("refresh token request failed with status %d: %s", refreshRr.Code, refreshRr.Body.String())
	}

	// Parse refresh token response
	var refreshResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(refreshRr.Body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("failed to unmarshal refresh token response: %v", err)
	}

	// Verify new access token is different
	if refreshResp.AccessToken == tokenResp.AccessToken {
		t.Error("expected new access token to be different from original")
	}

	// Verify we can still get a refresh token
	if refreshResp.RefreshToken == "" {
		t.Error("expected refresh token in refresh response")
	}
}

// TestServeAuthorize verifies OAuth authorization endpoint security and validation logic.
func TestServeAuthorize(t *testing.T) {
	tests := []struct {
		name           string
		clientID       string
		redirectURI    string
		state          string
		nonce          string
		clientRedirect string
		useFunnel      bool // whether to simulate funnel request
		mockWhoIsError bool // whether to make WhoIs return an error
		isTaggedNode   bool // whether to make IsTagged return true
		expectCode     int
	}{
		// Security boundary test: funnel rejection
		{
			name:           "funnel requests are always rejected for security",
			clientID:       "test-client",
			redirectURI:    "https://rp.example.com/callback",
			state:          "random-state",
			nonce:          "random-nonce",
			clientRedirect: "https://rp.example.com/callback",
			useFunnel:      true,
			expectCode:     http.StatusUnauthorized,
		},

		// parameter validation tests (non-funnel)
		{
			name:        "missing client_id",
			clientID:    "",
			redirectURI: "https://rp.example.com/callback",
			useFunnel:   false,
			expectCode:  http.StatusBadRequest,
		},
		{
			name:        "missing redirect_uri",
			clientID:    "test-client",
			redirectURI: "",
			useFunnel:   false,
			expectCode:  http.StatusBadRequest,
		},

		// client validation tests (non-funnel)
		{
			name:        "invalid client_id",
			clientID:    "invalid-client",
			redirectURI: "https://rp.example.com/callback",
			useFunnel:   false,
			expectCode:  http.StatusBadRequest,
		},
		{
			name:           "redirect_uri mismatch",
			clientID:       "test-client",
			redirectURI:    "https://wrong.example.com/callback",
			clientRedirect: "https://rp.example.com/callback",
			useFunnel:      false,
			expectCode:     http.StatusBadRequest,
		},

		// other cases
		{
			name:           "WhoIs error blocks flow",
			clientID:       "test-client",
			redirectURI:    "https://rp.example.com/callback",
			clientRedirect: "https://rp.example.com/callback",
			mockWhoIsError: true,
			expectCode:     http.StatusInternalServerError,
		},
		{
			name:           "tagged node is not allowed",
			clientID:       "test-client",
			redirectURI:    "https://rp.example.com/callback",
			clientRedirect: "https://rp.example.com/callback",
			isTaggedNode:   true,
			expectCode:     http.StatusFound,
		},
		{
			name:           "successfully issues auth code",
			clientID:       "test-client",
			redirectURI:    "https://rp.example.com/callback",
			clientRedirect: "https://rp.example.com/callback",
			expectCode:     http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			whoisResponse := &apitype.WhoIsResponse{
				Node: &tailcfg.Node{},
			}
			if tt.isTaggedNode {
				whoisResponse.Node.Tags = append(whoisResponse.Node.Tags, "tag:authorize-test-tag")
			}

			var lc *local.Client
			if tt.mockWhoIsError {
				lc = newTestWhoIsClient(t, nil, true)
			} else {
				lc = newTestWhoIsClient(t, whoisResponse, false)
			}

			srv := setupTestServer(t, lc)

			// Setup client if needed
			srv.funnelClients["test-client"] = &FunnelClient{
				ID:           "test-client",
				Secret:       "test-secret",
				Name:         "Test Client",
				RedirectURIs: []string{"http://dummydomain.ts", tt.clientRedirect}, /* test it matches redirect at end of slice */
			}

			// Create request
			reqURL := "/authorize"

			query := url.Values{}
			if tt.clientID != "" {
				query.Set("client_id", tt.clientID)
			}
			if tt.redirectURI != "" {
				query.Set("redirect_uri", tt.redirectURI)
			}
			if tt.state != "" {
				query.Set("state", tt.state)
			}
			if tt.nonce != "" {
				query.Set("nonce", tt.nonce)
			}

			reqURL += "?" + query.Encode()
			req := httptest.NewRequest("GET", reqURL, nil)
			req.RemoteAddr = "127.0.0.1:12345"

			// Set funnel header only when explicitly testing funnel behavior
			if tt.useFunnel {
				req.Header.Set("Tailscale-Funnel-Request", "true")
			}

			rr := httptest.NewRecorder()
			srv.serveAuthorize(rr, req)

			if rr.Code != tt.expectCode {
				t.Errorf("expected status code %d, got %d: %s", tt.expectCode, rr.Code, rr.Body.String())
			}

			// For any other code, the error check above is the last step
			if tt.expectCode != http.StatusFound {
				return
			}

			location := rr.Header().Get("Location")
			if location == "" {
				t.Error("expected Location header in redirect response")
				return
			}

			// Parse the redirect URL to verify it contains a code
			redirectURL, err := url.Parse(location)
			if err != nil {
				t.Errorf("failed to parse redirect URL: %v", err)
				return
			}

			// For a tagged node, we expect an `access_denied` error as the last step
			if tt.isTaggedNode {
				errCode := redirectURL.Query().Get("error")
				if errCode != ecAccessDenied {
					t.Error("expected 'error' parameter in redirect URL to be 'access_denied'")
				}
				return
			}

			code := redirectURL.Query().Get("code")
			if code == "" {
				t.Error("expected 'code' parameter in redirect URL")
			}

			// Verify state is preserved if provided
			if tt.state != "" {
				returnedState := redirectURL.Query().Get("state")
				if returnedState != tt.state {
					t.Errorf("expected state '%s', got '%s'", tt.state, returnedState)
				}
			}

			// Verify the auth request was stored
			srv.mu.Lock()
			ar, ok := srv.code[code]
			srv.mu.Unlock()

			if !ok {
				t.Error("expected authorization request to be stored")
				return
			}

			if ar.ClientID != tt.clientID {
				t.Errorf("expected clientID '%s', got '%s'", tt.clientID, ar.ClientID)
			}
			if ar.RedirectURI != tt.redirectURI {
				t.Errorf("expected redirectURI '%s', got '%s'", tt.redirectURI, ar.RedirectURI)
			}
			if ar.Nonce != tt.nonce {
				t.Errorf("expected nonce '%s', got '%s'", tt.nonce, ar.Nonce)
			}
		})
	}
}

func TestLastForwardedForAddr(t *testing.T) {
	tests := []struct {
		name string
		xff  []string // one r.Header.Add call per entry, in order
		want string
	}{
		{
			name: "no header",
			xff:  nil,
			want: "",
		},
		{
			name: "single header",
			xff:  []string{"100.64.0.1"},
			want: "100.64.0.1",
		},
		{
			name: "single header with surrounding whitespace is trimmed",
			xff:  []string{"  100.64.0.1  "},
			want: "100.64.0.1",
		},
		{
			name: "last header wins over client-supplied first header",
			// a client could set its own header first, but tailscaled's own header is always last
			xff:  []string{"100.64.0.99", "100.64.0.1"},
			want: "100.64.0.1",
		},
		{
			name: "comma-separated value in the last header uses the last segment",
			xff:  []string{"100.64.0.0", "100.64.0.1, 100.64.0.2"},
			want: "100.64.0.2",
		},
		{
			name: "trailing comma falls back to the last non-empty segment",
			xff:  []string{"100.64.0.1, 100.64.0.2,"},
			want: "100.64.0.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}

			if got := lastForwardedForAddr(r); got != tt.want {
				t.Errorf("lastForwardedForAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}
