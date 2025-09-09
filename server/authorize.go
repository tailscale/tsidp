// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/util/mak"
	"tailscale.com/util/rands"
)

// serveAuthorize handles the OAuth 2.0 authorization endpoint
func (s *IDPServer) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	// This URL is visited by the user who is being authenticated. If they are
	// visiting the URL over Funnel, that means they are not part of the
	// tailnet that they are trying to be authenticated for.
	// NOTE: Funnel request behavior is the same regardless of secure or insecure mode.
	if isFunnelRequest(r) {
		http.Error(w, "tsidp: unauthorized", http.StatusUnauthorized)
		return
	}
	uq := r.URL.Query()

	redirectURI := uq.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "tsidp: must specify redirect_uri", http.StatusBadRequest)
		return
	}

	clientID := uq.Get("client_id")
	if clientID == "" {
		http.Error(w, "tsidp: must specify client_id", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	funnelClient, ok := s.funnelClients[clientID]
	s.mu.Unlock()

	if !ok {
		http.Error(w, "tsidp: invalid client ID", http.StatusBadRequest)
		return
	}

	// Validate client_id matches (public identifier validation)
	clientIDcmp := subtle.ConstantTimeCompare([]byte(clientID), []byte(funnelClient.ID))
	if clientIDcmp != 1 {
		http.Error(w, "tsidp: invalid client ID", http.StatusBadRequest)
		return
	}

	// check for exact match of redirect_uri (OAuth 2.1 requirement)
	if !slices.Contains(funnelClient.RedirectURIs, redirectURI) {
		http.Error(w, "tsidp: redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	// Get user information
	var remoteAddr string
	if s.localTSMode {
		remoteAddr = r.Header.Get("X-Forwarded-For")
	} else {
		remoteAddr = r.RemoteAddr
	}

	// Check who is visiting the authorize endpoint.
	var who *apitype.WhoIsResponse
	var err error
	who, err = s.lc.WhoIs(r.Context(), remoteAddr)
	if err != nil {
		log.Printf("Error getting WhoIs: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate and save a code and Auth Request
	code := rands.HexString(32)
	ar := &AuthRequest{
		Nonce:       uq.Get("nonce"),
		RemoteUser:  who,
		RedirectURI: redirectURI,
		ClientID:    clientID,
		FunnelRP:    funnelClient, // Store the validated client
	}

	s.mu.Lock()
	mak.Set(&s.code, code, ar)
	s.mu.Unlock()

	queryString := make(url.Values)
	queryString.Set("code", code)
	if state := uq.Get("state"); state != "" {
		queryString.Set("state", state)
	}
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect URI", http.StatusInternalServerError)
		return
	}
	parsedURL.RawQuery = queryString.Encode()
	u := parsedURL.String()
	log.Printf("Redirecting to %q", u)

	http.Redirect(w, r, u, http.StatusFound)
}

// validateScopes validates the requested OAuth scopes
// Migrated from legacy/tsidp.go:399-423
func (s *IDPServer) validateScopes(requestedScopes []string) ([]string, error) {
	if len(requestedScopes) == 0 {
		// Default to openid scope if none specified
		return []string{"openid"}, nil
	}

	validatedScopes := make([]string, 0, len(requestedScopes))
	supportedScopes := openIDSupportedScopes.AsSlice()

	for _, scope := range requestedScopes {
		supported := false
		for _, supportedScope := range supportedScopes {
			if scope == supportedScope {
				supported = true
				break
			}
		}
		if !supported {
			return nil, fmt.Errorf("unsupported scope: %q", scope)
		}
		validatedScopes = append(validatedScopes, scope)
	}

	return validatedScopes, nil
}
