// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMetadataEndpoints tests OpenID Connect Discovery and OAuth 2.0 Authorization Server Metadata endpoints
func TestMetadataEndpoints(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		isFunnel     bool
		expectRegURL bool // Should registration_endpoint be present
	}{
		{
			name:         "OpenID metadata - tailnet",
			endpoint:     "/.well-known/openid-configuration",
			isFunnel:     false,
			expectRegURL: true,
		},
		{
			name:         "OpenID metadata - funnel",
			endpoint:     "/.well-known/openid-configuration",
			isFunnel:     true,
			expectRegURL: false,
		},
		{
			name:         "OAuth metadata - tailnet",
			endpoint:     "/.well-known/oauth-authorization-server",
			isFunnel:     false,
			expectRegURL: true,
		},
		{
			name:         "OAuth metadata - funnel",
			endpoint:     "/.well-known/oauth-authorization-server",
			isFunnel:     true,
			expectRegURL: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IDPServer{
				serverURL:   "https://idp.test.ts.net",
				loopbackURL: "http://localhost:8080",
			}

			req := httptest.NewRequest("GET", tt.endpoint, nil)
			req.RemoteAddr = "127.0.0.1:12345"
			if tt.isFunnel {
				req.Header.Set("Tailscale-Funnel-Request", "true")
			}

			rr := httptest.NewRecorder()

			if strings.Contains(tt.endpoint, "openid") {
				s.serveOpenIDConfig(rr, req)
			} else {
				s.serveOAuthMetadata(rr, req)
			}

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rr.Code)
			}

			var metadata map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &metadata); err != nil {
				t.Fatalf("failed to unmarshal metadata: %v", err)
			}

			// Check issuer
			if issuer, ok := metadata["issuer"].(string); !ok || issuer == "" {
				t.Error("missing or invalid issuer in metadata")
			}

			// Check endpoints are present
			expectedEndpoints := []string{
				"authorization_endpoint",
				"token_endpoint",
				"jwks_uri",
			}

			// OpenID specific endpoints
			if strings.Contains(tt.endpoint, "openid") {
				expectedEndpoints = append(expectedEndpoints, "userinfo_endpoint")
			}

			for _, ep := range expectedEndpoints {
				if _, ok := metadata[ep].(string); !ok {
					t.Errorf("missing or invalid %s in metadata", ep)
				}
			}

			// Check registration endpoint based on funnel status
			if tt.expectRegURL {
				if _, ok := metadata["registration_endpoint"]; !ok {
					t.Error("expected registration_endpoint in metadata")
				}
			} else {
				if _, ok := metadata["registration_endpoint"]; ok {
					t.Error("unexpected registration_endpoint in metadata")
				}
			}
		})
	}
}

// TestOAuthMetadataRefreshTokenSupport tests that refresh_token grant is properly advertised
func TestOAuthMetadataRefreshTokenSupport(t *testing.T) {
	s := &IDPServer{
		serverURL:   "https://idp.test.ts.net",
		loopbackURL: "http://localhost:8080",
	}

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	s.serveOAuthMetadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Check that refresh_token is in grant_types_supported
	grantTypes, ok := metadata["grant_types_supported"].([]interface{})
	if !ok {
		t.Fatal("grant_types_supported not found or wrong type")
	}

	found := false
	for _, gt := range grantTypes {
		if gtStr, ok := gt.(string); ok && gtStr == "refresh_token" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected refresh_token in grant_types_supported")
	}
}

// TestPKCEMetadata tests that PKCE methods are properly advertised in metadata
func TestPKCEMetadata(t *testing.T) {
	s := &IDPServer{
		serverURL:   "https://idp.test.ts.net",
		loopbackURL: "http://localhost:8080",
	}

	tests := []struct {
		name     string
		endpoint string
		checkFn  func(t *testing.T, metadata map[string]interface{})
	}{
		{
			name:     "OpenID Connect metadata",
			endpoint: "/.well-known/openid-configuration",
			checkFn: func(t *testing.T, metadata map[string]interface{}) {
				methods, ok := metadata["code_challenge_methods_supported"].([]interface{})
				if !ok {
					t.Fatal("code_challenge_methods_supported not found or wrong type")
				}
				if len(methods) != 2 {
					t.Errorf("expected 2 methods, got %d", len(methods))
				}
				expectedMethods := map[string]bool{"plain": true, "S256": true}
				for _, m := range methods {
					method, ok := m.(string)
					if !ok {
						t.Errorf("method is not a string: %T", m)
						continue
					}
					if !expectedMethods[method] {
						t.Errorf("unexpected method: %s", method)
					}
					delete(expectedMethods, method)
				}
				if len(expectedMethods) > 0 {
					t.Errorf("missing methods: %v", expectedMethods)
				}
			},
		},
		{
			name:     "OAuth 2.0 metadata",
			endpoint: "/.well-known/oauth-authorization-server",
			checkFn: func(t *testing.T, metadata map[string]interface{}) {
				methods, ok := metadata["code_challenge_methods_supported"].([]interface{})
				if !ok {
					t.Fatal("code_challenge_methods_supported not found or wrong type")
				}
				if len(methods) != 2 {
					t.Errorf("expected 2 methods, got %d", len(methods))
				}
				// Check that both plain and S256 are present
				methodSet := make(map[string]bool)
				for _, m := range methods {
					if method, ok := m.(string); ok {
						methodSet[method] = true
					}
				}
				if !methodSet["plain"] || !methodSet["S256"] {
					t.Error("expected both 'plain' and 'S256' methods to be supported")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.endpoint, nil)
			req.RemoteAddr = "127.0.0.1:12345"

			rr := httptest.NewRecorder()

			if strings.Contains(tt.endpoint, "openid") {
				s.serveOpenIDConfig(rr, req)
			} else {
				s.serveOAuthMetadata(rr, req)
			}

			if rr.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", rr.Code)
			}

			var metadata map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &metadata); err != nil {
				t.Fatalf("failed to unmarshal metadata: %v", err)
			}

			tt.checkFn(t, metadata)
		})
	}
}

// TestMetadataSTSSupport tests that STS token exchange grant is properly advertised when enabled
func TestMetadataSTSSupport(t *testing.T) {
	tests := []struct {
		name           string
		enableSTS      bool
		expectSTSGrant bool
	}{
		{
			name:           "STS disabled",
			enableSTS:      false,
			expectSTSGrant: false,
		},
		{
			name:           "STS enabled",
			enableSTS:      true,
			expectSTSGrant: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IDPServer{
				serverURL:   "https://idp.test.ts.net",
				loopbackURL: "http://localhost:8080",
				enableSTS:   tt.enableSTS,
			}

			req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
			req.RemoteAddr = "127.0.0.1:12345"

			rr := httptest.NewRecorder()
			s.serveOAuthMetadata(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rr.Code)
			}

			var metadata map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &metadata); err != nil {
				t.Fatalf("failed to unmarshal metadata: %v", err)
			}

			// Check grant_types_supported
			grantTypes, ok := metadata["grant_types_supported"].([]interface{})
			if !ok {
				t.Fatal("grant_types_supported not found or wrong type")
			}

			foundSTS := false
			for _, gt := range grantTypes {
				if gtStr, ok := gt.(string); ok && gtStr == "urn:ietf:params:oauth:grant-type:token-exchange" {
					foundSTS = true
					break
				}
			}

			if tt.expectSTSGrant && !foundSTS {
				t.Error("expected STS token exchange grant in grant_types_supported")
			}
			if !tt.expectSTSGrant && foundSTS {
				t.Error("unexpected STS token exchange grant in grant_types_supported")
			}
		})
	}
}

// TestJWKSEndpoint tests the JWKS endpoint
func TestJWKSEndpoint(t *testing.T) {
	s := &IDPServer{
		serverURL:   "https://idp.test.ts.net",
		loopbackURL: "http://localhost:8080",
		stateDir:    t.TempDir(),
	}

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	s.serveJWKS(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Check Content-Type
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	// Parse JWKS response
	var jwks map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("failed to unmarshal JWKS: %v", err)
	}

	// Check that keys array exists
	keys, ok := jwks["keys"].([]interface{})
	if !ok {
		t.Fatal("keys not found in JWKS or wrong type")
	}

	if len(keys) != 1 {
		t.Errorf("expected 1 key in JWKS, got %d", len(keys))
	}

	// Check the key has required fields
	if len(keys) > 0 {
		key, ok := keys[0].(map[string]interface{})
		if !ok {
			t.Fatal("key is not a map")
		}

		requiredFields := []string{"kty", "use", "kid", "n", "e"}
		for _, field := range requiredFields {
			if _, ok := key[field]; !ok {
				t.Errorf("missing required field %s in JWK", field)
			}
		}

		// Check specific values
		if kty, ok := key["kty"].(string); !ok || kty != "RSA" {
			t.Error("expected kty to be RSA")
		}
		if use, ok := key["use"].(string); !ok || use != "sig" {
			t.Error("expected use to be sig")
		}
	}
}
func TestMetadataCORSHeaders(t *testing.T) {
	s := &IDPServer{
		serverURL:   "https://idp.test.ts.net",
		loopbackURL: "http://localhost:8080",
	}

	for _, endpoint := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest("OPTIONS", endpoint, nil)
			req.RemoteAddr = "127.0.0.1:12345"

			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)

			if rr.Code != http.StatusNoContent {
				t.Errorf("expected status 204, got %d", rr.Code)
			}

			// extract the CORS headers
			accessControlAllowOrigin := rr.Header().Get("Access-Control-Allow-Origin")
			accessControlAllowMethods := rr.Header().Get("Access-Control-Allow-Methods")
			accessControlAllowHeaders := rr.Header().Get("Access-Control-Allow-Headers")

			if accessControlAllowOrigin != "*" {
				t.Errorf("expected Access-Control-Allow-Origin to be '*', got %s", accessControlAllowOrigin)
			}

			if accessControlAllowMethods != "GET, OPTIONS" {
				t.Errorf("expected Access-Control-Allow-Methods to be 'GET, OPTIONS', got %s", accessControlAllowMethods)
			}

			if accessControlAllowHeaders != "*" {
				t.Errorf("expected AccessControl-Allow-Headers to be '*', got %s", accessControlAllowHeaders)
			}
		})
	}
}
