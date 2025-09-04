// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
	"tailscale.com/util/rands"
)

// authorize handles the OAuth 2.0 authorization endpoint
// Migrated from legacy/tsidp.go:554-672
func (s *IDPServer) authorize(w http.ResponseWriter, r *http.Request) {
	// This URL is visited by the user who is being authenticated. If they are
	// visiting the URL over Funnel, that means they are not part of the
	// tailnet that they are trying to be authenticated for.
	if isFunnelRequest(r) {
		http.Error(w, "tsidp: unauthorized", http.StatusUnauthorized)
		return
	}

	uq := r.URL.Query()
	state := uq.Get("state")

	redirectURI := uq.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "tsidp: must specify redirect_uri", http.StatusBadRequest)
		return
	}

	var remoteAddr string
	if s.localTSMode {
		// in local tailscaled mode, the local tailscaled is forwarding us
		// HTTP requests, so reading r.RemoteAddr will just get us our own
		// address.
		remoteAddr = r.Header.Get("X-Forwarded-For")
	} else {
		remoteAddr = r.RemoteAddr
	}
	who, err := s.lc.WhoIs(r.Context(), remoteAddr)
	if err != nil {
		log.Printf("Error getting WhoIs: %v", err)
		redirectAuthError(w, r, redirectURI, "server_error", "internal server error", state)
		return
	}

	code := rands.HexString(32)
	ar := &AuthRequest{
		Nonce:       uq.Get("nonce"),
		RemoteUser:  who,
		RedirectURI: redirectURI,
		ClientID:    uq.Get("client_id"),
		Resources:   uq["resource"], // RFC 8707: multiple resource parameters are allowed
	}

	// Parse space-delimited scopes
	if scopeParam := uq.Get("scope"); scopeParam != "" {
		ar.Scopes = strings.Fields(scopeParam)
	}

	// Validate scopes
	validatedScopes, err := s.validateScopes(ar.Scopes)
	if err != nil {
		redirectAuthError(w, r, redirectURI, "invalid_scope", fmt.Sprintf("invalid scope: %v", err), state)
		return
	}
	ar.Scopes = validatedScopes

	// Handle PKCE parameters (RFC 7636)
	if codeChallenge := uq.Get("code_challenge"); codeChallenge != "" {
		ar.CodeChallenge = codeChallenge

		// code_challenge_method defaults to "plain" if not specified
		ar.CodeChallengeMethod = uq.Get("code_challenge_method")
		if ar.CodeChallengeMethod == "" {
			ar.CodeChallengeMethod = "plain"
		}

		// Validate the code_challenge_method
		if ar.CodeChallengeMethod != "plain" && ar.CodeChallengeMethod != "S256" {
			redirectAuthError(w, r, redirectURI, "invalid_request", "unsupported code_challenge_method", state)
			return
		}
	}

	if r.URL.Path == "/authorize/funnel" {
		s.mu.Lock()
		c, ok := s.funnelClients[ar.ClientID]
		s.mu.Unlock()
		if !ok {
			redirectAuthError(w, r, redirectURI, "invalid_request", "invalid client ID", state)
			return
		}
		// Validate redirect_uri against the client's registered redirect URIs
		validRedirect := false
		for _, uri := range c.RedirectURIs {
			if ar.RedirectURI == uri {
				validRedirect = true
				break
			}
		}
		if !validRedirect {
			redirectAuthError(w, r, redirectURI, "invalid_request", "redirect_uri mismatch", state)
			return
		}
		ar.FunnelRP = c
	} else if r.URL.Path == "/authorize/localhost" {
		ar.LocalRP = true
	} else {
		var ok bool
		ar.RPNodeID, ok = parseID[tailcfg.NodeID](strings.TrimPrefix(r.URL.Path, "/authorize/"))
		if !ok {
			redirectAuthError(w, r, redirectURI, "invalid_request", "invalid node ID suffix after /authorize/", state)
			return
		}
	}

	s.mu.Lock()
	mak.Set(&s.code, code, ar)
	s.mu.Unlock()

	q := make(url.Values)
	q.Set("code", code)
	if state := uq.Get("state"); state != "" {
		q.Set("state", state)
	}
	u := redirectURI + "?" + q.Encode()
	log.Printf("Redirecting to %q", u)

	http.Redirect(w, r, u, http.StatusFound)
}

// redirectAuthError redirects to the redirect_uri with an error
// Migrated from legacy/tsidp.go:1655-1674
func redirectAuthError(w http.ResponseWriter, r *http.Request, redirectURI, errorCode, errorDescription, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// If redirect URI is invalid, return error directly
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	q := u.Query()
	q.Set("error", errorCode)
	if errorDescription != "" {
		q.Set("error_description", errorDescription)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// parseID parses an ID from a string
// Migrated from legacy/tsidp.go:2377-2389
func parseID[T ~int64](input string) (_ T, ok bool) {
	if input == "" {
		return 0, false
	}
	i, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return 0, false
	}
	if i < 0 {
		return 0, false
	}
	return T(i), true
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