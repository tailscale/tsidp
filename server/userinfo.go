// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

// userInfo represents the OpenID Connect UserInfo response
// Migrated from legacy/tsidp.go:771-777
type userInfo struct {
	Sub      string `json:"sub"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Username string `json:"username,omitempty"`
}

// toMap converts userInfo to a map[string]any, using JSON struct tag names
// this is more reliable than marshaling to JSON for claims merging
func (ui userInfo) toMap() map[string]any {
	m := make(map[string]any)

	// Sub is always included (required field)
	m["sub"] = ui.Sub

	// Add optional fields only if they have values
	if ui.Name != "" {
		m["name"] = ui.Name
	}
	if ui.Email != "" {
		m["email"] = ui.Email
	}
	if ui.Picture != "" {
		m["picture"] = ui.Picture
	}
	if ui.Username != "" {
		m["username"] = ui.Username
	}

	return m
}

// serveUserInfo handles the /userinfo endpoint
// Migrated from legacy/tsidp.go:694-769
func (s *IDPServer) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
		return
	}
	tk, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeBearerError(w, http.StatusBadRequest, ecInvalidRequest, "invalid Authorization header")
		return
	}

	s.mu.Lock()
	ar, ok := s.accessToken[tk]
	s.mu.Unlock()
	if !ok {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}

	if ar.ValidTill.Before(time.Now()) {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "token expired")
		s.mu.Lock()
		delete(s.accessToken, tk)
		s.mu.Unlock()
		return
	}

	ui := userInfo{}
	if ar.RemoteUser.Node.IsTagged() {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "tagged nodes not supported", nil)
		return
	}

	// Sub is always included (openid scope is mandatory)
	ui.Sub = ar.RemoteUser.Node.User.String()

	// Always include user profile information if available
	ui.Name = ar.RemoteUser.UserProfile.DisplayName
	ui.Picture = ar.RemoteUser.UserProfile.ProfilePicURL
	ui.Email = s.realishEmail(ar.RemoteUser.UserProfile.LoginName)
	if username, _, ok := strings.Cut(ar.RemoteUser.UserProfile.LoginName, "@"); ok {
		ui.Username = username
	}

	rules, err := tailcfg.UnmarshalCapJSON[capRule](ar.RemoteUser.CapMap, tailcfg.PeerCapabilityTsIDP)
	if err != nil {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "failed to unmarshal capability", err)
		return
	}

	// Only keep rules where IncludeInUserInfo is true
	var filtered []capRule
	for _, r := range rules {
		if r.IncludeInUserInfo {
			filtered = append(filtered, r)
		}
	}

	userInfoMap, err := withExtraClaims(ui.toMap(), filtered)
	if err != nil {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "failed to process user claims", err)
		return
	}

	// Write the final result
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfoMap); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to encode user info", err)
	}
}

// writeBearerError writes an RFC 6750 compliant Bearer token error response
// with WWW-Authenticate header per section 3.1
// Migrated from legacy/tsidp.go:1643-1651
func writeBearerError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	// Build WWW-Authenticate header value
	authHeader := fmt.Sprintf(`Bearer error="%s"`, errorCode)
	if errorDescription != "" {
		authHeader += fmt.Sprintf(`, error_description="%s"`, errorDescription)
	}
	w.Header().Set("WWW-Authenticate", authHeader)
	w.WriteHeader(statusCode)
}

// addClaimValue adds a claim value to the deduplication set for a given claim key.
// It accepts scalars (string, int, float64), slices of strings or interfaces,
// and recursively handles nested slices. Unsupported types are ignored with a log message.
// Migrated from legacy/tsidp.go:845-875
func addClaimValue(sets map[string]map[string]struct{}, claim string, val any) {
	switch v := val.(type) {
	case string, float64, int, int64:
		// Ensure the claim set is initialized
		if sets[claim] == nil {
			sets[claim] = make(map[string]struct{})
		}
		// Add the stringified scalar to the set
		sets[claim][fmt.Sprintf("%v", v)] = struct{}{}

	case []string:
		// Ensure the claim set is initialized
		if sets[claim] == nil {
			sets[claim] = make(map[string]struct{})
		}
		// Add each string value to the set
		for _, s := range v {
			sets[claim][s] = struct{}{}
		}

	case []any:
		// Recursively handle each item in the slice
		for _, item := range v {
			addClaimValue(sets, claim, item)
		}

	default:
		// Log unsupported types for visibility and debugging
		slog.Warn("unsupported claim type",
			slog.String("claim", claim),
			slog.Any("value", v),
			slog.String("type", fmt.Sprintf("%T", v)),
		)
	}
}
