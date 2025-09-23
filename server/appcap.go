// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"context"
	"net/http"
	"net/netip"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// shared key for context values
var appCapCtxKey = &accessGrantedRules{}

// Capability rule types
type capRule struct {
	IncludeInUserInfo bool           `json:"includeInUserInfo"`
	ExtraClaims       map[string]any `json:"extraClaims,omitempty"` // list of features peer is allowed to edit

	// for sts rules
	Users     []string `json:"users"`     // list of users allowed to access resources (supports "*" wildcard)
	Resources []string `json:"resources"` // list of audience/resource URIs the user can access

	// allow lists
	AllowAdminUI bool `json:"allow_admin_ui"`
	AllowDCR     bool `json:"allow_dcr"` // dynamic client registration
}

// AccessGrantedRules holds the access rules from granted Application Capabilities.
// tsidp uses a deny-all-by-default model, so only the granted capabilities are allowed
type accessGrantedRules struct {
	allowAdminUI bool
	allowDCR     bool
	rules        []capRule // list of rules
}

// addGrantAccessContext wraps an http.HandlerFunc and adds a AccessGrantedRules to the
// *http.Request's context. Handlers that are protected by an Application capability grant
// can conventiently extract and check the granted capabilities.
func (s *IDPServer) addGrantAccessContext(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// used only for testing to bypass app cap checks
		if s.bypassAppCapCheck {
			r = r.WithContext(context.WithValue(r.Context(), appCapCtxKey, &accessGrantedRules{
				allowAdminUI: true,
				allowDCR:     true,
				rules:        []capRule{}, // empty rules for testing
			}))
			handler(w, r)
			return
		}

		// when local.Client is not available send through a default-deny rules
		if s.lc == nil {
			r = r.WithContext(context.WithValue(r.Context(), appCapCtxKey, &accessGrantedRules{
				rules: []capRule{}, // empty rules for testing
			}))
			handler(w, r)
			return
		}

		// allow all access when requests are coming from localhost
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			if ap.Addr().IsLoopback() {
				r = r.WithContext(context.WithValue(r.Context(), appCapCtxKey, &accessGrantedRules{
					allowAdminUI: true,
					allowDCR:     true,
					rules:        []capRule{},
				}))
				handler(w, r)
				return
			}
		}

		// Build the access rules from granted application capabilities
		accessRules := &accessGrantedRules{}

		var remoteAddr string
		if s.localTSMode {
			remoteAddr = r.Header.Get("X-Forwarded-For")
		} else {
			remoteAddr = r.RemoteAddr
		}

		var who *apitype.WhoIsResponse
		var err error

		who, err = s.lc.WhoIs(r.Context(), remoteAddr)
		if err != nil {
			writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "Error getting WhoIs", err)
			return
		}

		rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, "tailscale.com/cap/tsidp")
		if err != nil {
			writeHTTPError(w, r, http.StatusInternalServerError, ecServerError, "failed unmarshaling app cap rule", err)
			return
		}
		accessRules.rules = rules

		// grant rules are accumulated from all granted rules
		for _, rule := range rules {
			if rule.AllowAdminUI {
				accessRules.allowAdminUI = true
			}
			if rule.AllowDCR {
				accessRules.allowDCR = true
			}
		}

		r = r.WithContext(context.WithValue(r.Context(), appCapCtxKey, accessRules))
		handler(w, r)
	}
}
