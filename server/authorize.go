// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/util/mak"
	"tailscale.com/util/rands"
)

// serveAuthorize handles the OAuth 2.0 authorization endpoint
func (s *IDPServer) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	// This URL is visited by the user who is being authenticated. If they are
	// visiting the URL over Funnel, that means they are not part of the
	// tailnet that they are trying to be authenticated for.
	if isFunnelRequest(r) {
		writeHTTPError(w, r, http.StatusUnauthorized, ecAccessDenied, "not allowed over funnel", nil)
		return
	}

	uq := r.URL.Query()
	state := uq.Get("state")

	redirectURI := uq.Get("redirect_uri")
	if redirectURI == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "must specify redirect_uri", nil)
		return
	}

	clientID := uq.Get("client_id")
	if clientID == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "must specify client_id", nil)
		return
	}

	s.mu.Lock()
	funnelClient, ok := s.funnelClients[clientID]
	s.mu.Unlock()

	if !ok {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidClient, "invalid client ID", nil)
		return
	}

	// Validate client_id matches (public identifier validation)
	clientIDcmp := subtle.ConstantTimeCompare([]byte(clientID), []byte(funnelClient.ID))
	if clientIDcmp != 1 {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidClient, "invalid client ID", nil)
		return
	}

	// check for exact match of redirect_uri (OAuth 2.1 requirement)
	if !slices.Contains(funnelClient.RedirectURIs, redirectURI) {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "redirect_uri mismatch", nil)
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
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to authenticate user with WhoIs", err)
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
			redirectAuthError(w, r, redirectURI, ecInvalidRequest, "unsupported code_challenge_method", state)
			return
		}
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
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "invalid redirect URI", err)
		return
	}
	parsedURL.RawQuery = queryString.Encode()
	u := parsedURL.String()
	slog.Debug("authorize redirect", slog.String("url", u))
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

// redirectAuthError redirects to the client's redirect_uri with error parameters
// per RFC 6749 Section 4.1.2.1
func redirectAuthError(w http.ResponseWriter, r *http.Request, redirectURI, errorCode, errorDescription, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// If redirect URI is invalid, return error directly
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "invalid redirect_uri", err)
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

	slog.Info("Redirecting to client with error",
		slog.String("error_code", errorCode),
		slog.String("state", state),
		slog.String("redirect_uri", u.String()),
	)
	http.Redirect(w, r, u.String(), http.StatusFound)
}
