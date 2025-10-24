// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

//go:embed ui-header.html
var headerHTML string

//go:embed ui-list.html
var listHTML string

//go:embed ui-edit.html
var editHTML string

//go:embed ui-style.css
var styleCSS string

var tmplFuncs = template.FuncMap{
	"joinRedirectURIs": joinRedirectURIs,
}

var headerTmpl = template.Must(template.New("header").Funcs(tmplFuncs).Parse(headerHTML))
var listTmpl = template.Must(headerTmpl.New("list").Parse(listHTML))
var editTmpl = template.Must(headerTmpl.New("edit").Parse(editHTML))

var processStart = time.Now()

// handleUI serves the UI for managing OAuth/OIDC clients
// Migrated from legacy/ui.go:61-85
func (s *IDPServer) handleUI(w http.ResponseWriter, r *http.Request) {
	if isFunnelRequest(r) {
		writeHTTPError(w, r, http.StatusUnauthorized, ecAccessDenied, "not available over funnel", nil)
		return
	}

	access, ok := r.Context().Value(appCapCtxKey).(*accessGrantedRules)
	if !ok {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "application capability not found", nil)
		return
	}

	if !access.allowAdminUI {
		writeHTTPError(w, r, http.StatusForbidden, ecAccessDenied, "application capability not granted", nil)
		return
	}

	switch r.URL.Path {
	case "/":
		s.handleClientsList(w, r)
		return
	case "/new":
		s.handleNewClient(w, r)
		return
	case "/style.css":
		http.ServeContent(w, r, "ui-style.css", processStart, strings.NewReader(styleCSS))
		return
	}

	if strings.HasPrefix(r.URL.Path, "/edit/") {
		s.handleEditClient(w, r)
		return
	}

	writeHTTPError(w, r, http.StatusNotFound, ecNotFound, "not found", nil)
}

// handleClientsList displays the list of configured OAuth/OIDC clients
// Migrated from legacy/ui.go:87-113
func (s *IDPServer) handleClientsList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	clients := make([]clientDisplayData, 0, len(s.funnelClients))
	for _, c := range s.funnelClients {
		clients = append(clients, clientDisplayData{
			ID:           c.ID,
			Name:         c.Name,
			RedirectURIs: c.RedirectURIs,
			HasSecret:    c.Secret != "",
		})
	}
	s.mu.Unlock()

	sort.Slice(clients, func(i, j int) bool {
		if clients[i].Name != clients[j].Name {
			return clients[i].Name < clients[j].Name
		}
		return clients[i].ID < clients[j].ID
	})

	var buf bytes.Buffer
	if err := listTmpl.Execute(&buf, clients); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to render client list", err)
		return
	}
	buf.WriteTo(w)
}

// handleNewClient handles creating a new OAuth/OIDC client
// Migrated from legacy/ui.go:115-186
func (s *IDPServer) handleNewClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "Method not allowed", nil)
	}

	if err := s.renderClientForm(w, clientDisplayData{IsNew: true}); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to render form", err)
	}
}

// handleEditClient handles editing an existing OAuth/OIDC client
func (s *IDPServer) handleEditClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "Method not allowed", nil)
	}

	clientID := strings.TrimPrefix(r.URL.Path, "/edit/")
	if clientID == "" {
		writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "Client ID required", nil)
		return
	}

	s.mu.Lock()
	client, exists := s.funnelClients[clientID]
	s.mu.Unlock()

	if !exists {
		writeHTTPError(w, r, http.StatusNotFound, ecNotFound, "Client not found", nil)
		return
	}

	data := clientDisplayData{
		ID:           client.ID,
		Name:         client.Name,
		RedirectURIs: client.RedirectURIs,
		HasSecret:    client.Secret != "",
		IsEdit:       true,
	}
	if err := s.renderClientForm(w, data); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to render form", err)
	}
}

// clientDisplayData holds data for rendering client forms and lists
// Migrated from legacy/ui.go:321-331
type clientDisplayData struct {
	ID           string
	Name         string
	RedirectURIs []string
	Secret       string
	HasSecret    bool
	IsNew        bool
	IsEdit       bool
}

// renderClientForm renders the client edit/create form
// Migrated from legacy/ui.go:333-342
func (s *IDPServer) renderClientForm(w http.ResponseWriter, data clientDisplayData) error {
	var buf bytes.Buffer
	if err := editTmpl.Execute(&buf, data); err != nil {
		return err
	}
	if _, err := buf.WriteTo(w); err != nil {
		return err
	}
	return nil
}

// validateRedirectURI validates that a redirect URI is well-formed
func validateRedirectURI(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" {
		return "must be a valid URI with a scheme"
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		if u.Host == "" {
			return "HTTP and HTTPS URLs must have a host"
		}
	}
	return ""
}
