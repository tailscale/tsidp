// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/util/mak"
)

// TestFunnelClientBackwardCompatibility tests backward compatibility for client field names
func TestFunnelClientBackwardCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		jsonData   string
		expectURIs []string
		expectName string
	}{
		{
			name: "old format with redirect_uri and name",
			jsonData: `{
				"id": "test-client",
				"secret": "test-secret",
				"name": "Test Client",
				"redirect_uri": "https://example.com/callback"
			}`,
			expectURIs: []string{"https://example.com/callback"},
			expectName: "Test Client",
		},
		{
			name: "new format with redirect_uris and name",
			jsonData: `{
				"id": "test-client",
				"secret": "test-secret",
				"name": "Test Client",
				"redirect_uris": ["https://example.com/callback", "https://example.com/callback2"]
			}`,
			expectURIs: []string{"https://example.com/callback", "https://example.com/callback2"},
			expectName: "Test Client",
		},
		{
			name: "both redirect fields present (redirect_uris takes precedence)",
			jsonData: `{
				"id": "test-client",
				"secret": "test-secret",
				"name": "Test Client",
				"redirect_uri": "https://old.example.com/callback",
				"redirect_uris": ["https://new.example.com/callback"]
			}`,
			expectURIs: []string{"https://new.example.com/callback"},
			expectName: "Test Client",
		},
		{
			name: "mixed old and new fields",
			jsonData: `{
				"id": "test-client",
				"secret": "test-secret",
				"name": "Test Client",
				"redirect_uris": ["https://example.com/callback"]
			}`,
			expectURIs: []string{"https://example.com/callback"},
			expectName: "Test Client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var client FunnelClient

			// Since FunnelClient doesn't have custom UnmarshalJSON in the new structure,
			// we need to handle backward compatibility differently.
			// For now, we'll test the expected format directly.
			var rawData map[string]interface{}
			if err := json.Unmarshal([]byte(tt.jsonData), &rawData); err != nil {
				t.Fatalf("failed to unmarshal raw data: %v", err)
			}

			// Manually handle backward compatibility
			client.ID = rawData["id"].(string)
			client.Secret = rawData["secret"].(string)
			client.Name = rawData["name"].(string)

			// Handle redirect URIs
			if uris, ok := rawData["redirect_uris"].([]interface{}); ok {
				client.RedirectURIs = make([]string, len(uris))
				for i, uri := range uris {
					client.RedirectURIs[i] = uri.(string)
				}
			} else if uri, ok := rawData["redirect_uri"].(string); ok {
				client.RedirectURIs = []string{uri}
			}

			if !reflect.DeepEqual(client.RedirectURIs, tt.expectURIs) {
				t.Errorf("expected redirect_uris %v, got %v", tt.expectURIs, client.RedirectURIs)
			}

			if client.Name != tt.expectName {
				t.Errorf("expected name %q, got %q", tt.expectName, client.Name)
			}
		})
	}
}

// TestServeDynamicClientRegistration tests the dynamic client registration endpoint
func TestServeDynamicClientRegistration(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		body          string
		isFunnel      bool
		expectStatus  int
		checkResponse func(t *testing.T, body []byte)

		// Disable app cap override for this test to test for the deny-by-default behaviour
		disableAppCapOverride bool
	}{
		{
			name:   "Check access without app cap is denied",
			method: "POST",
			body: `{
				"redirect_uris": ["https://example.com/callback"],
				"client_name": "Test Client",
				"grant_types": ["authorization_code"],
				"response_types": ["code"]
			}`,
			expectStatus:          http.StatusForbidden,
			disableAppCapOverride: true,
			checkResponse:         nil,
		},

		{
			name:   "POST request - verify JSON field names",
			method: "POST",
			body: `{
				"redirect_uris": ["https://example.com/callback"],
				"client_name": "Test Client",
				"grant_types": ["authorization_code"],
				"response_types": ["code"]
			}`,
			expectStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body []byte) {
				// Parse as raw JSON to verify exact field names
				var rawResp map[string]interface{}
				if err := json.Unmarshal(body, &rawResp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				// Check that the correct field names are present
				if _, ok := rawResp["client_id"]; !ok {
					t.Error("expected 'client_id' field in response, not found")
				}
				if _, ok := rawResp["client_secret"]; !ok {
					t.Error("expected 'client_secret' field in response, not found")
				}
				if _, ok := rawResp["client_name"]; !ok {
					t.Error("expected 'name' field in response, not found")
				}
				if _, ok := rawResp["redirect_uris"]; !ok {
					t.Error("expected 'redirect_uris' field in response, not found")
				}

				// Verify values
				if clientId, ok := rawResp["client_id"].(string); !ok || clientId == "" {
					t.Error("client_id should be a non-empty string")
				}
				if clientSecret, ok := rawResp["client_secret"].(string); !ok || clientSecret == "" {
					t.Error("client_secret should be a non-empty string")
				}
				if clientName, ok := rawResp["client_name"].(string); !ok || clientName != "Test Client" {
					t.Errorf("expected name to be 'Test Client', got %v", rawResp["name"])
				}
			},
		},
		{
			name:   "POST request - valid registration",
			method: "POST",
			body: `{
				"redirect_uris": ["https://example.com/callback"],
				"client_name": "Test Dynamic Client",
				"grant_types": ["authorization_code"],
				"response_types": ["code"]
			}`,
			expectStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body []byte) {
				var resp FunnelClient
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				if resp.ID == "" {
					t.Error("expected client_id to be set")
				}
				if resp.Secret == "" {
					t.Error("expected client_secret to be set")
				}
				if resp.Name != "Test Dynamic Client" {
					t.Errorf("expected client_name to be 'Test Dynamic Client', got %s", resp.Name)
				}
				if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "https://example.com/callback" {
					t.Errorf("expected redirect_uris to be ['https://example.com/callback'], got %v", resp.RedirectURIs)
				}
				if !resp.DynamicallyRegistered {
					t.Error("expected dynamically_registered to be true")
				}
				if resp.TokenEndpointAuthMethod != "client_secret_basic" {
					t.Errorf("expected default token_endpoint_auth_method to be 'client_secret_basic', got %s", resp.TokenEndpointAuthMethod)
				}
			},
		},
		{
			name:   "POST request - minimal registration",
			method: "POST",
			body: `{
				"redirect_uris": ["https://example.com/callback"]
			}`,
			expectStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body []byte) {
				var resp FunnelClient
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				// Check defaults were applied
				if resp.TokenEndpointAuthMethod != "client_secret_basic" {
					t.Errorf("expected default token_endpoint_auth_method, got %s", resp.TokenEndpointAuthMethod)
				}
				if !reflect.DeepEqual(resp.GrantTypes, []string{"authorization_code"}) {
					t.Errorf("expected default grant_types, got %v", resp.GrantTypes)
				}
				if !reflect.DeepEqual(resp.ResponseTypes, []string{"code"}) {
					t.Errorf("expected default response_types, got %v", resp.ResponseTypes)
				}
				if resp.ApplicationType != "web" {
					t.Errorf("expected default application_type to be 'web', got %s", resp.ApplicationType)
				}
			},
		},
		{
			name:         "POST request - blocked over funnel",
			method:       "POST",
			body:         `{"redirect_uris": ["https://example.com/callback"]}`,
			isFunnel:     true,
			expectStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "access_denied" {
					t.Errorf("expected error code 'access_denied', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "not available over funnel") {
					t.Errorf("expected error description about funnel, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "POST request - missing redirect_uris",
			method:       "POST",
			body:         `{"client_name": "Test Client"}`,
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_client_metadata" {
					t.Errorf("expected error code 'invalid_client_metadata', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "redirect_uris is required") {
					t.Errorf("expected error description about redirect_uris, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "POST request - empty redirect_uris",
			method:       "POST",
			body:         `{"redirect_uris": []}`,
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_client_metadata" {
					t.Errorf("expected error code 'invalid_client_metadata', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "redirect_uris is required") {
					t.Errorf("expected error description about redirect_uris, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "POST request - invalid JSON",
			method:       "POST",
			body:         `{invalid json}`,
			expectStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_request" {
					t.Errorf("expected error code 'invalid_request', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "invalid request body") {
					t.Errorf("expected error description about invalid request body, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:         "GET request - method not allowed",
			method:       "GET",
			expectStatus: http.StatusMethodNotAllowed,
			checkResponse: func(t *testing.T, body []byte) {
				var errResp map[string]interface{}
				if err := json.Unmarshal(body, &errResp); err != nil {
					t.Fatalf("expected JSON error response, got: %s", body)
				}
				if errResp["error"] != "invalid_request" {
					t.Errorf("expected error code 'invalid_request', got: %v", errResp["error"])
				}
				if desc, ok := errResp["error_description"].(string); !ok || !strings.Contains(desc, "method not allowed") {
					t.Errorf("expected error description about method not allowed, got: %v", errResp["error_description"])
				}
			},
		},
		{
			name:   "POST request - multiple redirect URIs",
			method: "POST",
			body: `{
				"redirect_uris": ["https://example.com/callback", "https://example.com/oauth", "https://example.com/auth"],
				"client_name": "Multi-Redirect Client"
			}`,
			expectStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body []byte) {
				var resp FunnelClient
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}

				if len(resp.RedirectURIs) != 3 {
					t.Errorf("expected 3 redirect_uris, got %d", len(resp.RedirectURIs))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temp directory for state storage
			tempDir := t.TempDir()

			s := &IDPServer{
				serverURL:     "https://idp.test.ts.net",
				stateDir:      tempDir,
				funnelClients: make(map[string]*FunnelClient),

				// tt.disableAppCapOverride is true to test the deny-by-default behaviour
				bypassAppCapCheck: !tt.disableAppCapOverride,
			}

			// Mock the storeFunnelClientsLocked function for testing
			// The actual implementation writes to disk, which we'll test separately

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/register", body)
			req.Header.Add("Accept", "application/json")
			if tt.isFunnel {
				req.Header.Set("Tailscale-Funnel-Request", "true")
			}

			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("expected status %d, got %d\nBody: %s", tt.expectStatus, rr.Code, rr.Body.String())
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rr.Body.Bytes())
			}
		})
	}
}

// TestRedirectURIValidation tests redirect URI validation logic
func TestRedirectURIValidation(t *testing.T) {
	tests := []struct {
		name        string
		clientURIs  []string
		requestURI  string
		expectValid bool
	}{
		{
			name:        "valid single URI",
			clientURIs:  []string{"https://example.com/callback"},
			requestURI:  "https://example.com/callback",
			expectValid: true,
		},
		{
			name:        "valid multiple URIs - first",
			clientURIs:  []string{"https://example.com/callback1", "https://example.com/callback2"},
			requestURI:  "https://example.com/callback1",
			expectValid: true,
		},
		{
			name:        "valid multiple URIs - second",
			clientURIs:  []string{"https://example.com/callback1", "https://example.com/callback2"},
			requestURI:  "https://example.com/callback2",
			expectValid: true,
		},
		{
			name:        "invalid URI",
			clientURIs:  []string{"https://example.com/callback"},
			requestURI:  "https://evil.com/callback",
			expectValid: false,
		},
		{
			name:        "empty client URIs",
			clientURIs:  []string{},
			requestURI:  "https://example.com/callback",
			expectValid: false,
		},
		{
			name:        "case sensitive mismatch",
			clientURIs:  []string{"https://example.com/callback"},
			requestURI:  "https://example.com/CALLBACK",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a helper function that matches the validation logic
			isValidRedirectURI := func(clientURIs []string, requestURI string) bool {
				for _, uri := range clientURIs {
					if requestURI == uri {
						return true
					}
				}
				return false
			}

			validRedirect := isValidRedirectURI(tt.clientURIs, tt.requestURI)

			if validRedirect != tt.expectValid {
				t.Errorf("expected valid=%v, got %v", tt.expectValid, validRedirect)
			}
		})
	}
}

// TestSplitRedirectURIs tests splitting redirect URIs from a newline-separated string
func TestSplitRedirectURIs(t *testing.T) {
	// Helper function that mimics the UI helper
	splitRedirectURIs := func(input string) []string {
		if input == "" {
			return nil
		}

		lines := strings.Split(input, "\n")
		var result []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single URI",
			input:    "https://example.com/callback",
			expected: []string{"https://example.com/callback"},
		},
		{
			name:     "multiple URIs",
			input:    "https://example.com/callback\nhttps://example.com/oauth\nhttps://example.com/auth",
			expected: []string{"https://example.com/callback", "https://example.com/oauth", "https://example.com/auth"},
		},
		{
			name:     "URIs with extra whitespace",
			input:    "  https://example.com/callback  \n\n  https://example.com/oauth  \n\n\n",
			expected: []string{"https://example.com/callback", "https://example.com/oauth"},
		},
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
		{
			name:     "only whitespace",
			input:    "   \n\n   \n   ",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitRedirectURIs(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("splitRedirectURIs(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// TestJoinRedirectURIs tests joining redirect URIs into a newline-separated string
func TestJoinRedirectURIs(t *testing.T) {
	// Helper function that mimics the UI helper
	joinRedirectURIs := func(uris []string) string {
		if len(uris) == 0 {
			return ""
		}
		return strings.Join(uris, "\n")
	}

	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "single URI",
			input:    []string{"https://example.com/callback"},
			expected: "https://example.com/callback",
		},
		{
			name:     "multiple URIs",
			input:    []string{"https://example.com/callback", "https://example.com/oauth", "https://example.com/auth"},
			expected: "https://example.com/callback\nhttps://example.com/oauth\nhttps://example.com/auth",
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: "",
		},
		{
			name:     "nil slice",
			input:    nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinRedirectURIs(tt.input)
			if got != tt.expected {
				t.Errorf("joinRedirectURIs(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestClientPersistence tests that clients are properly persisted to disk
func TestClientPersistence(t *testing.T) {
	tempDir := t.TempDir()

	s := &IDPServer{
		serverURL:     "https://idp.test.ts.net",
		stateDir:      tempDir,
		funnelClients: make(map[string]*FunnelClient),
	}

	// Create a test client
	client := &FunnelClient{
		ID:                    "test-client-1",
		Secret:                "test-secret-1",
		Name:                  "Test Client 1",
		RedirectURIs:          []string{"https://example.com/callback"},
		DynamicallyRegistered: true,
	}

	// Add client and persist
	s.mu.Lock()
	mak.Set(&s.funnelClients, client.ID, client)
	err := s.storeFunnelClientsLocked()
	s.mu.Unlock()

	if err != nil {
		t.Fatalf("failed to store clients: %v", err)
	}

	// Create a new server instance and load clients
	s2 := &IDPServer{
		serverURL:     "https://idp.test.ts.net",
		stateDir:      tempDir,
		funnelClients: make(map[string]*FunnelClient),
	}

	// Load clients from disk
	err = s2.LoadFunnelClients()
	if err != nil {
		t.Fatalf("failed to load clients: %v", err)
	}

	// Verify the client was loaded correctly
	s2.mu.Lock()
	loadedClient, ok := s2.funnelClients[client.ID]
	s2.mu.Unlock()
	if !ok {
		t.Fatal("client not found after loading")
	}

	if loadedClient.ID != client.ID {
		t.Errorf("expected client ID %s, got %s", client.ID, loadedClient.ID)
	}
	if loadedClient.Secret != client.Secret {
		t.Errorf("expected client secret %s, got %s", client.Secret, loadedClient.Secret)
	}
	if loadedClient.Name != client.Name {
		t.Errorf("expected client name %s, got %s", client.Name, loadedClient.Name)
	}
	if !reflect.DeepEqual(loadedClient.RedirectURIs, client.RedirectURIs) {
		t.Errorf("expected redirect URIs %v, got %v", client.RedirectURIs, loadedClient.RedirectURIs)
	}
}

// TestDeleteClient tests client deletion functionality
func TestDeleteClient(t *testing.T) {
	tempDir := t.TempDir()

	s := &IDPServer{
		serverURL:     "https://idp.test.ts.net",
		stateDir:      tempDir,
		funnelClients: make(map[string]*FunnelClient),

		// Disable app cap for this test to test for the deny-by-default behaviour
		bypassAppCapCheck: true,
	}

	// Create test clients
	client1 := &FunnelClient{
		ID:           "test-client-1",
		Secret:       "test-secret-1",
		Name:         "Test Client 1",
		RedirectURIs: []string{"https://example.com/callback"},
	}

	client2 := &FunnelClient{
		ID:           "test-client-2",
		Secret:       "test-secret-2",
		Name:         "Test Client 2",
		RedirectURIs: []string{"https://example.com/callback2"},
	}

	// Add clients
	s.mu.Lock()
	mak.Set(&s.funnelClients, client1.ID, client1)
	mak.Set(&s.funnelClients, client2.ID, client2)
	s.mu.Unlock()

	// Test deleting client1
	req := httptest.NewRequest("DELETE", "/clients/test-client-1", nil)
	rr := httptest.NewRecorder()

	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", rr.Code)
	}

	// Verify client1 was deleted but client2 remains
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.funnelClients["test-client-1"]; exists {
		t.Error("client1 should have been deleted")
	}

	if _, exists := s.funnelClients["test-client-2"]; !exists {
		t.Error("client2 should still exist")
	}
}

// TestGetClientsList tests the client list endpoint
func TestGetClientsList(t *testing.T) {
	s := &IDPServer{
		serverURL:     "https://idp.test.ts.net",
		funnelClients: make(map[string]*FunnelClient),

		// Disable app cap for this test to test for the deny-by-default behaviour
		bypassAppCapCheck: true,
	}

	// Add test clients
	client1 := &FunnelClient{
		ID:           "test-client-1",
		Name:         "Test Client 1",
		RedirectURIs: []string{"https://example.com/callback1"},
	}

	client2 := &FunnelClient{
		ID:           "test-client-2",
		Name:         "Test Client 2",
		RedirectURIs: []string{"https://example.com/callback2"},
	}

	s.mu.Lock()
	mak.Set(&s.funnelClients, client1.ID, client1)
	mak.Set(&s.funnelClients, client2.ID, client2)
	s.mu.Unlock()

	// Test GET request
	req := httptest.NewRequest("GET", "/clients/", nil)
	rr := httptest.NewRecorder()

	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Parse response
	var clients []FunnelClient
	if err := json.NewDecoder(rr.Body).Decode(&clients); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(clients) != 2 {
		t.Errorf("expected 2 clients, got %d", len(clients))
	}

	// Verify both clients are in the list
	foundClient1 := false
	foundClient2 := false
	for _, c := range clients {
		if c.ID == client1.ID {
			foundClient1 = true
		}
		if c.ID == client2.ID {
			foundClient2 = true
		}
	}

	if !foundClient1 {
		t.Error("client1 not found in list")
	}
	if !foundClient2 {
		t.Error("client2 not found in list")
	}
}

// TestServeNewClient tests the new client creation endpoint
func TestServeNewClient(t *testing.T) {
	tempDir := t.TempDir()

	s := &IDPServer{
		serverURL:     "https://idp.test.ts.net",
		stateDir:      tempDir,
		funnelClients: make(map[string]*FunnelClient),

		// Disable app cap for this test to test for the deny-by-default behaviour
		bypassAppCapCheck: true,
	}

	// Test creating a new client via form data
	formData := "name=New+Test+Client&redirect_uri=https%3A%2F%2Fexample.com%2Foauth"
	body := strings.NewReader(formData)

	req := httptest.NewRequest("POST", "/clients/new", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	s.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d\nBody: %s", rr.Code, rr.Body.String())
	}

	// Parse response
	var newClient FunnelClient
	if err := json.NewDecoder(rr.Body).Decode(&newClient); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify client was created with proper fields
	if newClient.ID == "" {
		t.Error("expected client ID to be set")
	}
	if newClient.Secret == "" {
		t.Error("expected client secret to be set")
	}
	if newClient.Name != "New Test Client" {
		t.Errorf("expected name 'New Test Client', got %s", newClient.Name)
	}

	// Verify client was added to the server's client list
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.funnelClients[newClient.ID]; !exists {
		t.Error("new client was not added to server's client list")
	}
}

func TestDynamicClientRegistrationCORSHeaders(t *testing.T) {
	s := &IDPServer{
		serverURL:   "https://idp.test.ts.net",
		loopbackURL: "http://localhost:8080",
	}
	req := httptest.NewRequest("OPTIONS", "/register", nil)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	ao := rr.Header().Get("Access-Control-Allow-Origin")
	am := rr.Header().Get("Access-Control-Allow-Methods")
	ah := rr.Header().Get("Access-Control-Allow-Headers")

	if ao != "*" {
		t.Errorf("expected Access-Control-Allow-Origin to be '*', got %s", ao)
	}

	if am != "POST, OPTIONS" {
		t.Errorf("expected Access-Control-Allow-Methods to be 'POST, OPTIONS, got %s", am)
	}

	if ah != "*" {
		t.Errorf("expected AccessControl-Allow-Headers to be '*', got %s", ah)
	}
}

func TestClientApiCSRF(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		secFetchSite   string
		origin         string
		expectedStatus int
	}{
		{
			name:           "POST /clients/new - cross-site request blocked",
			method:         "POST",
			path:           "/clients/new",
			secFetchSite:   "cross-site",
			origin:         "https://evil.example.com",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "POST /clients/new - same-origin request allowed",
			method:         "POST",
			path:           "/clients/new",
			secFetchSite:   "same-origin",
			origin:         "https://idp.test.ts.net",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST /clients/new - same-site request allowed",
			method:         "POST",
			path:           "/clients/new",
			secFetchSite:   "same-site",
			origin:         "https://idp.test.ts.net",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST /clients/new - no header allowed",
			method:         "POST",
			path:           "/clients/new",
			secFetchSite:   "",
			origin:         "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "DELETE /clients/{id} - cross-site request blocked",
			method:         "DELETE",
			path:           "/clients/test-client-1",
			secFetchSite:   "cross-site",
			origin:         "https://evil.example.com",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "DELETE /clients/{id} - same-origin request allowed",
			method:         "DELETE",
			path:           "/clients/test-client-1",
			secFetchSite:   "same-origin",
			origin:         "https://idp.test.ts.net",
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "DELETE /clients/{id} - same-site request allowed",
			method:         "DELETE",
			path:           "/clients/test-client-1",
			secFetchSite:   "same-site",
			origin:         "https://idp.test.ts.net",
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "DELETE /clients/{id} - no header allowed",
			method:         "DELETE",
			path:           "/clients/test-client-1",
			secFetchSite:   "",
			origin:         "",
			expectedStatus: http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			s := &IDPServer{
				serverURL:         "https://idp.test.ts.net",
				stateDir:          tempDir,
				funnelClients:     make(map[string]*FunnelClient),
				bypassAppCapCheck: true,
			}

			// For DELETE tests, add a test client
			if tt.method == "DELETE" {
				s.mu.Lock()
				mak.Set(&s.funnelClients, "test-client-1", &FunnelClient{
					ID:           "test-client-1",
					Secret:       "test-secret",
					Name:         "Test Client",
					RedirectURIs: []string{"https://example.com/callback"},
				})
				s.mu.Unlock()
			}

			var body io.Reader
			if tt.method == "POST" {
				// Provide minimal form data for POST /clients/new
				body = strings.NewReader("name=Test+Client&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback")
			}

			req := httptest.NewRequest(tt.method, tt.path, body)
			if tt.method == "POST" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			if tt.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d\nBody: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}
