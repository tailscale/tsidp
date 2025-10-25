// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"tailscale.com/util/rands"
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
	if r.Method == "GET" {
		if err := s.renderClientForm(w, clientDisplayData{IsNew: true}); err != nil {
			writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to render form", err)
		}
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "Failed to parse form", err)
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		redirectURIsText := strings.TrimSpace(r.FormValue("redirect_uris"))
		redirectURIs := splitRedirectURIs(redirectURIsText)

		baseData := clientDisplayData{
			IsNew:        true,
			Name:         name,
			RedirectURIs: redirectURIs,
		}

		if len(redirectURIs) == 0 {
			s.renderFormError(w, r, baseData, "At least one redirect URI is required")
			return
		}

		for _, uri := range redirectURIs {
			if errMsg := validateRedirectURI(uri); errMsg != "" {
				s.renderFormError(w, r, baseData, fmt.Sprintf("Invalid redirect URI '%s': %s", uri, errMsg))
				return
			}
		}

		clientID := rands.HexString(32)
		clientSecret := rands.HexString(64)
		newClient := FunnelClient{
			ID:           clientID,
			Secret:       clientSecret,
			Name:         name,
			RedirectURIs: redirectURIs,
		}

		s.mu.Lock()
		if s.funnelClients == nil {
			s.funnelClients = make(map[string]*FunnelClient)
		}
		s.funnelClients[clientID] = &newClient
		err := s.storeFunnelClientsLocked()
		s.mu.Unlock()

		if err != nil {
			slog.Error("client create: could not write funnel clients db", slog.Any("error", err))
			s.renderFormError(w, r, baseData, "Failed to save client")
			return
		}

		successData := clientDisplayData{
			ID:           clientID,
			Name:         name,
			RedirectURIs: redirectURIs,
			Secret:       clientSecret,
			IsNew:        true,
		}
		s.renderFormSuccess(w, r, successData, "Client created successfully! Save the client secret - it won't be shown again.")
		return
	}

	writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "Method not allowed", nil)
}

// handleEditClient handles editing an existing OAuth/OIDC client
// Migrated from legacy/ui.go:188-319
func (s *IDPServer) handleEditClient(w http.ResponseWriter, r *http.Request) {
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

	if r.Method == "GET" {
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
		return
	}

	if r.Method == "POST" {
		action := r.FormValue("action")

		if action == "delete" {
			s.mu.Lock()
			delete(s.funnelClients, clientID)
			err := s.storeFunnelClientsLocked()
			s.mu.Unlock()

			if err != nil {
				slog.Error("client delete: could not write funnel clients db", slog.Any("error", err))
				s.mu.Lock()
				s.funnelClients[clientID] = client
				s.mu.Unlock()

				baseData := clientDisplayData{
					ID:           client.ID,
					Name:         client.Name,
					RedirectURIs: client.RedirectURIs,
					HasSecret:    client.Secret != "",
					IsEdit:       true,
				}
				s.renderFormError(w, r, baseData, "Failed to delete client. Please try again.")
				return
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if action == "regenerate_secret" {
			newSecret := rands.HexString(64)
			s.mu.Lock()
			s.funnelClients[clientID].Secret = newSecret
			err := s.storeFunnelClientsLocked()
			s.mu.Unlock()

			baseData := clientDisplayData{
				ID:           client.ID,
				Name:         client.Name,
				RedirectURIs: client.RedirectURIs,
				HasSecret:    true,
				IsEdit:       true,
			}

			if err != nil {
				slog.Error("client regen secret: could not write funnel clients db", slog.Any("error", err))
				s.renderFormError(w, r, baseData, "Failed to regenerate secret")
				return
			}

			baseData.Secret = newSecret
			s.renderFormSuccess(w, r, baseData, "New client secret generated! Save it - it won't be shown again.")
			return
		}

		if err := r.ParseForm(); err != nil {
			writeHTTPError(w, r, http.StatusBadRequest, ecInvalidRequest, "Failed to parse form", err)
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		redirectURIsText := strings.TrimSpace(r.FormValue("redirect_uris"))
		redirectURIs := splitRedirectURIs(redirectURIsText)
		baseData := clientDisplayData{
			ID:           client.ID,
			Name:         name,
			RedirectURIs: redirectURIs,
			HasSecret:    client.Secret != "",
			IsEdit:       true,
		}

		if len(redirectURIs) == 0 {
			s.renderFormError(w, r, baseData, "At least one redirect URI is required")
			return
		}

		for _, uri := range redirectURIs {
			if errMsg := validateRedirectURI(uri); errMsg != "" {
				s.renderFormError(w, r, baseData, fmt.Sprintf("Invalid redirect URI '%s': %s", uri, errMsg))
				return
			}
		}

		s.mu.Lock()
		s.funnelClients[clientID].Name = name
		s.funnelClients[clientID].RedirectURIs = redirectURIs
		err := s.storeFunnelClientsLocked()
		s.mu.Unlock()

		if err != nil {
			slog.Error("client update: could not write funnel clients db", slog.Any("error", err))
			s.renderFormError(w, r, baseData, "Failed to update client")
			return
		}

		s.renderFormSuccess(w, r, baseData, "Client updated successfully!")
		return
	}

	writeHTTPError(w, r, http.StatusMethodNotAllowed, ecInvalidRequest, "Method not allowed", nil)
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
	Success      string
	Error        string
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

// renderFormError renders the form with an error message
// Migrated from legacy/ui.go:344-349
func (s *IDPServer) renderFormError(w http.ResponseWriter, r *http.Request, data clientDisplayData, errorMsg string) {
	data.Error = errorMsg
	if err := s.renderClientForm(w, data); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to render form", err)
	}
}

// renderFormSuccess renders the form with a success message
// Migrated from legacy/ui.go:351-356
func (s *IDPServer) renderFormSuccess(w http.ResponseWriter, r *http.Request, data clientDisplayData, successMsg string) {
	data.Success = successMsg
	if err := s.renderClientForm(w, data); err != nil {
		writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed to render form", err)
	}
}

// isDangerousScheme returns true if the scheme should not be allowed
// in OAuth redirect URIs due to security risks.
// The reason for not simply allowlisting http/https is that some native apps can handle
// special scheme prefixes as an intentional integration.
func isDangerousScheme(scheme string) bool {
	switch scheme {
	case "ftp", "file", "mailto", "javascript", "data",
		"blob", "filesystem", "vbscript", "about",
		"chrome", "chrome-extension":
		return true
	}
	return false
}

// validateRedirectURI validates that a redirect URI is well-formed
func validateRedirectURI(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" {
		return "must be a valid URI with a scheme"
	}

	if isDangerousScheme(u.Scheme) {
		return fmt.Sprintf("scheme %q is not allowed", u.Scheme)
	}

	if u.Scheme == "http" || u.Scheme == "https" {
		if u.Host == "" {
			return "HTTP and HTTPS URLs must have a host"
		}
	}
	return ""
}
