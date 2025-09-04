// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"tailscale.com/tailcfg"
)

// userInfo represents the OpenID Connect UserInfo response
// Migrated from legacy/tsidp.go:771-777
type userInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	Email             string `json:"email,omitempty"`
	Picture           string `json:"picture,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

// serveUserInfo handles the /userinfo endpoint
// Migrated from legacy/tsidp.go:694-769
func (s *IDPServer) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tk, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeBearerError(w, http.StatusBadRequest, "invalid_request", "invalid Authorization header")
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
		http.Error(w, "tsidp: tagged nodes not supported", http.StatusBadRequest)
		return
	}

	// Sub is always included (openid scope is mandatory)
	ui.Sub = ar.RemoteUser.Node.User.String()

	// Check scopes and only include claims that were authorized
	for _, scope := range ar.Scopes {
		switch scope {
		case "profile":
			ui.Name = ar.RemoteUser.UserProfile.DisplayName
			ui.Picture = ar.RemoteUser.UserProfile.ProfilePicURL
			if username, _, ok := strings.Cut(ar.RemoteUser.UserProfile.LoginName, "@"); ok {
				ui.PreferredUsername = username
			}
		case "email":
			ui.Email = ar.RemoteUser.UserProfile.LoginName
		}
	}

	rules, err := tailcfg.UnmarshalCapJSON[capRule](ar.RemoteUser.CapMap, tailcfg.PeerCapabilityTsIDP)
	if err != nil {
		http.Error(w, fmt.Sprintf("tsidp: failed to unmarshal capability: %v", err), http.StatusBadRequest)
		return
	}

	// Only keep rules where IncludeInUserInfo is true
	var filtered []capRule
	for _, r := range rules {
		if r.IncludeInUserInfo {
			filtered = append(filtered, r)
		}
	}

	userInfoMap, err := withExtraClaimsGeneric(ui, filtered)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Write the final result
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfoMap); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

// withExtraClaimsGeneric merges flattened extra claims from a list of capRule into the provided struct v,
// returning a map[string]any that combines both sources.
// This is a more generic version that works with any struct type.
// Migrated from legacy/tsidp.go:888-919
func withExtraClaimsGeneric(v any, rules []capRule) (map[string]any, error) {
	// Marshal the static struct
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// Unmarshal into a generic map
	var claimMap map[string]any
	if err := json.Unmarshal(data, &claimMap); err != nil {
		return nil, err
	}

	// Convert views.Slice to a map[string]struct{} for efficient lookup
	protected := make(map[string]struct{}, len(openIDSupportedClaims.AsSlice()))
	for _, claim := range openIDSupportedClaims.AsSlice() {
		protected[claim] = struct{}{}
	}

	// Merge extra claims
	extra := flattenExtraClaims(rules)
	for k, v := range extra {
		if _, isProtected := protected[k]; isProtected {
			log.Printf("Skip overwriting of existing claim %q", k)
			return nil, fmt.Errorf("extra claim %q overwriting existing claim", k)
		}

		claimMap[k] = v
	}

	return claimMap, nil
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
		log.Printf("Unsupported claim type for %q: %#v (type %T)", claim, val, val)
	}
}