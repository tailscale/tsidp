// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/util/rands"
)

// FunnelClient represents an OAuth/OIDC client configuration
// Migrated from legacy/tsidp.go:2006-2024
type FunnelClient struct {
	ID                      string    `json:"client_id"`
	Secret                  string    `json:"client_secret,omitempty"`
	Name                    string    `json:"client_name,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string  `json:"grant_types,omitempty"`
	ResponseTypes           []string  `json:"response_types,omitempty"`
	Scope                   string    `json:"scope,omitempty"`
	ClientURI               string    `json:"client_uri,omitempty"`
	LogoURI                 string    `json:"logo_uri,omitempty"`
	Contacts                []string  `json:"contacts,omitempty"`
	ApplicationType         string    `json:"application_type,omitempty"`
	DynamicallyRegistered   bool      `json:"dynamically_registered,omitempty"`
	CreatedAt               time.Time `json:"created_at"`

	// backwards compatibility for old clients that used a single string
	RedirectURI string `json:"redirect_uri"`
}

const funnelClientsFile = "oidc-funnel-clients.json"

// SetFunnelClients sets the funnel clients
func (s *IDPServer) SetFunnelClients(clients map[string]*FunnelClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.funnelClients = clients
}

// getFunnelClientsPath returns the path to the funnel clients file
func (s *IDPServer) getFunnelClientsPath() string {
	if s.stateDir != "" {
		return filepath.Join(s.stateDir, funnelClientsFile)
	}
	return funnelClientsFile
}

// LoadFunnelClients loads funnel clients from disk
func (s *IDPServer) LoadFunnelClients() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.getFunnelClientsPath())
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, which is okay
			return nil
		}
		return err
	}
	defer f.Close()

	var clients map[string]*FunnelClient
	if err := json.NewDecoder(f).Decode(&clients); err != nil {
		return err
	}

	s.funnelClients = clients

	// migrate old configurations that used a single redirect_uri field
	migrationPerformed := false
	for _, c := range s.funnelClients {

		// only perform migration if there's a redirect_uri and no redirect_uris yet
		if c.RedirectURI != "" && len(c.RedirectURIs) == 0 {
			c.RedirectURIs = append(c.RedirectURIs, c.RedirectURI)
			migrationPerformed = true
		}
	}
	if migrationPerformed {
		slog.Info("Migrated old funnel clients with single redirect_uri to redirect_uris field.")
		if err := s.storeFunnelClientsLocked(); err != nil {
			return fmt.Errorf("failed to store migrated clients: %w", err)
		}
	}

	return nil
}

// storeFunnelClientsLocked persists the funnel clients to disk
// Caller must hold s.mu lock
// Migrated from legacy/tsidp.go:2270-2276
func (s *IDPServer) storeFunnelClientsLocked() error {
	var buf bytes.Buffer

	// backwards compat. add a redirect_uri field so clients are compatible with older tsidp versions
	for _, c := range s.funnelClients {
		if c.RedirectURI == "" && len(c.RedirectURIs) > 0 {
			c.RedirectURI = c.RedirectURIs[0] // Use the first redirect URI for backwards compatibility
		}
	}

	if err := json.NewEncoder(&buf).Encode(s.funnelClients); err != nil {
		return err
	}

	return os.WriteFile(s.getFunnelClientsPath(), buf.Bytes(), 0600)
}

// serveClients handles the /clients/ endpoints for managing OAuth clients
// Migrated from legacy/tsidp.go:2055-2094
func (s *IDPServer) serveClients(w http.ResponseWriter, r *http.Request) {
	if isFunnelRequest(r) {
		writeHTTPError(w, r, http.StatusUnauthorized, ecAccessDenied, "not available over funnel", nil)
		return
	}

	access, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
	if !ok {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "application capability not found", nil)
		return
	}

	// require the same level of access as the main admin UI.
	// Note: the admin UI has its own endpoints /, /new, /edit/{id}, for managing clients.
	if !access.allowAdminUI {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "application capability not granted", nil)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/clients/")
	if path == "new" {
		s.serveNewClient(w, r)
		return
	}

	if path == "" {
		s.serveGetClientsList(w, r)
		return
	}

	s.mu.Lock()
	c, ok := s.funnelClients[path]
	s.mu.Unlock()

	if !ok {
		writeHTTPError(w, r, http.StatusNotFound, ecNotFound, "client not found", nil)
		return
	}

	switch r.Method {
	case "DELETE":
		s.serveDeleteClient(w, r, path)
	case "GET":
		json.NewEncoder(w).Encode(&FunnelClient{
			ID:           c.ID,
			Name:         c.Name,
			Secret:       "",
			RedirectURIs: c.RedirectURIs,
		})
	default:
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
	}
}

// serveNewClient creates a new OAuth client
// Migrated from legacy/tsidp.go:2096-2126
func (s *IDPServer) serveNewClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
		return
	}
	redirectURI := r.FormValue("redirect_uri")
	name := r.FormValue("name")
	if redirectURI == "" || name == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "missing redirect_uri or name", nil)
		return
	}

	clientID := generateClientID()
	clientSecret := generateClientSecret()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.funnelClients == nil {
		s.funnelClients = make(map[string]*FunnelClient)
	}

	client := &FunnelClient{
		ID:           clientID,
		Secret:       clientSecret,
		Name:         name,
		RedirectURIs: splitRedirectURIs(redirectURI),
		CreatedAt:    time.Now(),
	}

	s.funnelClients[clientID] = client

	if err := s.storeFunnelClientsLocked(); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to store client", err)
		return
	}

	json.NewEncoder(w).Encode(client)
}

// serveGetClientsList returns a list of all OAuth clients
// Migrated from legacy/tsidp.go:2128-2145
func (s *IDPServer) serveGetClientsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	clients := make([]*FunnelClient, 0, len(s.funnelClients))
	for _, c := range s.funnelClients {
		clients = append(clients, &FunnelClient{
			ID:           c.ID,
			Name:         c.Name,
			Secret:       "", // Don't return secrets
			RedirectURIs: c.RedirectURIs,
			CreatedAt:    c.CreatedAt,
		})
	}

	json.NewEncoder(w).Encode(clients)
}

// serveDeleteClient deletes an OAuth client
// Migrated from legacy/tsidp.go:2239-2265
func (s *IDPServer) serveDeleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	if r.Method != "DELETE" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.funnelClients[clientID]; !ok {
		writeHTTPError(w, r, http.StatusNotFound, ecNotFound, "client not found", nil)
		return
	}

	delete(s.funnelClients, clientID)

	// Clean up any tokens associated with this client
	for code, ar := range s.code {
		if ar.ClientID == clientID {
			delete(s.code, code)
		}
	}
	for token, ar := range s.accessToken {
		if ar.ClientID == clientID {
			delete(s.accessToken, token)
		}
	}
	for token, ar := range s.refreshToken {
		if ar.ClientID == clientID {
			delete(s.refreshToken, token)
		}
	}

	if err := s.storeFunnelClientsLocked(); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to store clients", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// serveDynamicClientRegistration handles OAuth 2.0 Dynamic Client Registration (RFC 7591)
// Migrated from legacy/tsidp.go:2149-2237
func (s *IDPServer) serveDynamicClientRegistration(w http.ResponseWriter, r *http.Request) {
	// Block funnel requests - dynamic registration is only available over tailnet
	if isFunnelRequest(r) {
		writeHTTPError(w, r, http.StatusUnauthorized, ecAccessDenied, "not available over funnel", nil)
		return
	}

	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != "POST" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "method not allowed", nil)
		return
	}

	access, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
	if !ok {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "application capability not found", nil)
		return
	}

	if !access.allowDCR {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "application capability not granted", nil)
		return
	}

	var registrationRequest struct {
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
		GrantTypes              []string `json:"grant_types,omitempty"`
		ResponseTypes           []string `json:"response_types,omitempty"`
		ClientName              string   `json:"client_name,omitempty"`
		ClientURI               string   `json:"client_uri,omitempty"`
		LogoURI                 string   `json:"logo_uri,omitempty"`
		Scope                   string   `json:"scope,omitempty"`
		Contacts                []string `json:"contacts,omitempty"`
		ApplicationType         string   `json:"application_type,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&registrationRequest); err != nil {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "invalid request body", err)
		return
	}

	// Validate required fields
	if len(registrationRequest.RedirectURIs) == 0 {
		writeHTTPError(w, r, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required", nil)
		return
	}

	clientID := generateClientID()
	clientSecret := generateClientSecret()

	// Set defaults
	if registrationRequest.TokenEndpointAuthMethod == "" {
		registrationRequest.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if len(registrationRequest.GrantTypes) == 0 {
		registrationRequest.GrantTypes = []string{"authorization_code"}
	}
	if len(registrationRequest.ResponseTypes) == 0 {
		registrationRequest.ResponseTypes = []string{"code"}
	}
	if registrationRequest.ApplicationType == "" {
		registrationRequest.ApplicationType = "web"
	}

	client := &FunnelClient{
		ID:                      clientID,
		Secret:                  clientSecret,
		Name:                    registrationRequest.ClientName,
		RedirectURIs:            registrationRequest.RedirectURIs,
		TokenEndpointAuthMethod: registrationRequest.TokenEndpointAuthMethod,
		GrantTypes:              registrationRequest.GrantTypes,
		ResponseTypes:           registrationRequest.ResponseTypes,
		Scope:                   registrationRequest.Scope,
		ClientURI:               registrationRequest.ClientURI,
		LogoURI:                 registrationRequest.LogoURI,
		Contacts:                registrationRequest.Contacts,
		ApplicationType:         registrationRequest.ApplicationType,
		DynamicallyRegistered:   true,
		CreatedAt:               time.Now(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.funnelClients == nil {
		s.funnelClients = make(map[string]*FunnelClient)
	}

	s.funnelClients[clientID] = client

	if err := s.storeFunnelClientsLocked(); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to store client", err)
		return
	}

	// Return the client configuration as per RFC 7591
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(client)
}

// Helper functions for redirect URI handling
// Migrated from legacy/tsidp.go

// splitRedirectURIs splits a multi-line string of redirect URIs into a slice
func splitRedirectURIs(uris string) []string {
	if uris == "" {
		return nil
	}

	var result []string
	lines := strings.Split(uris, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// joinRedirectURIs joins a slice of redirect URIs into a multi-line string
func joinRedirectURIs(uris []string) string {
	if len(uris) == 0 {
		return ""
	}
	return strings.Join(uris, "\n")
}

// generateClientID generates a random client ID
func generateClientID() string {
	return rands.HexString(32)
}

// generateClientSecret generates a random client secret
func generateClientSecret() string {
	return rands.HexString(64)
}
