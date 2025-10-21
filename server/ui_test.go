// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
