// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestUIDenyOnMissingApplicationGrant(t *testing.T) {

	tests := []struct {
		name              string
		bypassAppCapCheck bool
		expectedStatus    int
	}{
		{name: "No UI Application Capability", bypassAppCapCheck: false, expectedStatus: http.StatusForbidden},
		{name: "Has UI application Capability", bypassAppCapCheck: true, expectedStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IDPServer{
				bypassAppCapCheck: tt.bypassAppCapCheck,
			}
			req := httptest.NewRequest("GET", "/", nil)
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{
			name: "valid HTTPS URL",
			uri:  "https://example.com/callback",
			want: "",
		},
		{
			name: "valid HTTP URL",
			uri:  "http://localhost:3000/callback",
			want: "",
		},
		{
			name: "valid mobile app scheme",
			uri:  "myapp://auth/callback",
			want: "",
		},
		{
			name: "valid custom scheme with subdomain",
			uri:  "com.example.app://callback",
			want: "",
		},
		{
			name: "valid scheme with path and query",
			uri:  "myapp://auth/callback?state=123",
			want: "",
		},
		{
			name: "missing scheme",
			uri:  "example.com/callback",
			want: "must be a valid URI with a scheme",
		},
		{
			name: "empty URI",
			uri:  "",
			want: "must be a valid URI with a scheme",
		},
		{
			name: "invalid URI",
			uri:  "ht tp://invalid",
			want: "must be a valid URI with a scheme",
		},
		{
			name: "HTTP URL missing host",
			uri:  "http:///callback",
			want: "HTTP and HTTPS URLs must have a host",
		},
		{
			name: "HTTPS URL missing host",
			uri:  "https:///callback",
			want: "HTTP and HTTPS URLs must have a host",
		},
		{
			name: "custom scheme without host is valid",
			uri:  "myapp:///callback",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateRedirectURI(tt.uri)
			if got != tt.want {
				t.Errorf("validateRedirectURI(%q) = %q, want %q", tt.uri, got, tt.want)
			}
		})
	}
}

func newClientForm(t *testing.T, values url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", "/new", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestHandleNewClientPublic(t *testing.T) {
	s := &IDPServer{
		funnelClients: make(map[string]*FunnelClient),
		stateDir:      t.TempDir(),
	}

	form := url.Values{
		"name":                       {"Incus"},
		"redirect_uris":              {"https://host.example.ts.net/oidc/callback"},
		"token_endpoint_auth_method": {"none"},
	}

	rr := httptest.NewRecorder()
	s.handleNewClient(rr, newClientForm(t, form))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	if strings.Contains(rr.Body.String(), "Client Secret") {
		t.Error("expected no Client Secret field in response for a public client")
	}
	if !strings.Contains(rr.Body.String(), "public client") {
		t.Error("expected response to explain this is a public client")
	}

	if len(s.funnelClients) != 1 {
		t.Fatalf("expected exactly one stored client, got %d", len(s.funnelClients))
	}
	for _, c := range s.funnelClients {
		if c.Secret != "" {
			t.Errorf("expected empty secret for public client, got %q", c.Secret)
		}
		if c.TokenEndpointAuthMethod != "none" {
			t.Errorf("expected TokenEndpointAuthMethod %q, got %q", "none", c.TokenEndpointAuthMethod)
		}
	}
}

func TestHandleNewClientConfidentialDefault(t *testing.T) {
	s := &IDPServer{
		funnelClients: make(map[string]*FunnelClient),
		stateDir:      t.TempDir(),
	}

	form := url.Values{
		"name":          {"My App"},
		"redirect_uris": {"https://example.com/callback"},
		// token_endpoint_auth_method intentionally omitted
	}

	rr := httptest.NewRecorder()
	s.handleNewClient(rr, newClientForm(t, form))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	if !strings.Contains(rr.Body.String(), "Client Secret") {
		t.Error("expected a Client Secret field in response for a confidential client")
	}

	if len(s.funnelClients) != 1 {
		t.Fatalf("expected exactly one stored client, got %d", len(s.funnelClients))
	}
	for _, c := range s.funnelClients {
		if c.Secret == "" {
			t.Error("expected a non-empty secret for confidential client")
		}
		if c.TokenEndpointAuthMethod != "client_secret_basic" {
			t.Errorf("expected TokenEndpointAuthMethod %q, got %q", "client_secret_basic", c.TokenEndpointAuthMethod)
		}
	}
}

func TestHandleEditClientPublicHidesRegenerate(t *testing.T) {
	s := &IDPServer{
		funnelClients: map[string]*FunnelClient{
			"public-client": {
				ID:                      "public-client",
				Name:                    "Incus",
				RedirectURIs:            []string{"https://host.example.ts.net/oidc/callback"},
				TokenEndpointAuthMethod: "none",
			},
		},
		stateDir: t.TempDir(),
	}

	req := httptest.NewRequest("GET", "/edit/public-client", nil)
	rr := httptest.NewRecorder()
	s.handleEditClient(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	if strings.Contains(body, "Regenerate Secret") {
		t.Error("expected no Regenerate Secret button for a public client")
	}
	if !strings.Contains(body, "Public (no secret, PKCE)") {
		t.Error("expected the read-only auth method to say Public")
	}
}

func TestHandleEditClientRegenerateSecretRejectedForPublicClient(t *testing.T) {
	s := &IDPServer{
		funnelClients: map[string]*FunnelClient{
			"public-client": {
				ID:                      "public-client",
				Name:                    "Incus",
				RedirectURIs:            []string{"https://host.example.ts.net/oidc/callback"},
				TokenEndpointAuthMethod: "none",
			},
		},
		stateDir: t.TempDir(),
	}

	form := url.Values{"action": {"regenerate_secret"}}
	req := httptest.NewRequest("POST", "/edit/public-client", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.handleEditClient(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "have a secret to regenerate") {
		t.Error("expected an error explaining public clients have no secret to regenerate")
	}
	if s.funnelClients["public-client"].Secret != "" {
		t.Error("expected secret to remain empty after rejected regenerate attempt")
	}
}

func TestUserInterfaceCSRF(t *testing.T) {
	tests := []struct {
		name           string
		secFetchSite   string
		origin         string
		expectedStatus int
	}{
		{
			name:           "cross-site request blocked",
			secFetchSite:   "cross-site",
			origin:         "https://evil.example.com",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "same-origin request allowed",
			secFetchSite:   "same-origin",
			origin:         "https://idp.test.ts.net",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "same-site request allowed",
			secFetchSite:   "same-site",
			origin:         "https://idp.test.ts.net",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "no header allowed",
			secFetchSite:   "",
			origin:         "",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &IDPServer{
				serverURL:         "https://idp.test.ts.net",
				bypassAppCapCheck: true,
			}
			req := httptest.NewRequest("POST", "/new", nil)
			if tt.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

// TestEditClientDeleteRevokesTokens checks that deleting a client in the web
// UI also removes its codes and tokens, as DELETE /clients/{id} does, and
// leaves other clients' tokens alone.
func TestEditClientDeleteRevokesTokens(t *testing.T) {
	alice := refreshRecheckWhoIs(501, "alice@example.com", nil)
	srv := setupTestServer(t, newTestWhoIsClient(t, alice, false))
	srv.refreshToken = make(map[string]*AuthRequest)
	srv.funnelClients["other-client"] = &FunnelClient{ID: "other-client", Secret: "other-secret"}

	for _, id := range []string{"test-client", "other-client"} {
		ar := &AuthRequest{
			ClientID:   id,
			FunnelRP:   srv.funnelClients[id],
			RemoteUser: alice,
			ValidTill:  time.Now().Add(time.Hour),
		}
		srv.code[id+"-code"] = ar
		srv.accessToken[id+"-at"] = ar
		srv.refreshToken[id+"-rt"] = ar
	}

	form := url.Values{"action": {"delete"}}
	req := httptest.NewRequest("POST", "/edit/test-client", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleEditClient(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("delete: got %d: %s", rr.Code, rr.Body.String())
	}
	if _, ok := srv.funnelClients["test-client"]; ok {
		t.Fatal("client still registered after delete")
	}

	stores := []struct {
		suffix string
		m      map[string]*AuthRequest
	}{
		{"-code", srv.code},
		{"-at", srv.accessToken},
		{"-rt", srv.refreshToken},
	}
	for _, st := range stores {
		if _, ok := st.m["test-client"+st.suffix]; ok {
			t.Errorf("test-client%s still present after delete", st.suffix)
		}
		if _, ok := st.m["other-client"+st.suffix]; !ok {
			t.Errorf("other-client%s was removed", st.suffix)
		}
	}

	// The deleted client's refresh token no longer works.
	form = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"test-client-rt"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req = httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	srv.serveToken(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), ecInvalidGrant) {
		t.Errorf("refresh after delete: got %d, want 400 invalid_grant", rr.Code)
	}
}
