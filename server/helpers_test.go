// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"testing"

	"gopkg.in/square/go-jose.v2"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// setupTestServerWithClient creates a test server with an optional LocalClient.
// If lc is nil, the server will have no LocalClient (original behavior).
// If lc is provided, it will be used for WhoIs calls during testing.
func setupTestServer(t *testing.T, lc *local.Client) *IDPServer {
	t.Helper()

	srv := &IDPServer{
		code:          make(map[string]*AuthRequest),
		accessToken:   make(map[string]*AuthRequest),
		funnelClients: make(map[string]*FunnelClient),
		serverURL:     "https://test.ts.net",
		stateDir:      t.TempDir(),
		lc:            lc,
	}

	// Add a test client
	srv.funnelClients["test-client"] = &FunnelClient{
		ID:          "test-client",
		Secret:      "test-secret",
		Name:        "Test Client",
		RedirectURI: "https://rp.example.com/callback",
	}

	// Inject a working signer for token tests
	srv.lazySigner.Set(oidcTestingSigner(t))

	return srv
}

// whoisRoundTripper is an http.RoundTripper that returns a canned WhoIs
// response. It is used to test code that calls local.Client.WhoIs without
// needing a running tailscaled.
type whoisRoundTripper struct {
	response *apitype.WhoIsResponse
	err      bool // if true, return HTTP 500
}

func (rt *whoisRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/localapi/v0/whois" {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}, nil
	}
	if rt.err {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(bytes.NewBufferString("whois error")),
		}, nil
	}
	b, _ := json.Marshal(rt.response)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}, nil
}

// newTestWhoIsClient returns a *local.Client whose WhoIs calls return the
// given response or an error. This uses local.Client's Transport field to
// intercept HTTP requests without needing a running tailscaled.
func newTestWhoIsClient(t *testing.T, whoisResponse *apitype.WhoIsResponse, whoisErr bool) *local.Client {
	t.Helper()
	return &local.Client{
		Transport: &whoisRoundTripper{response: whoisResponse, err: whoisErr},
	}
}

func mustMarshalJSON(t *testing.T, v any) tailcfg.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return tailcfg.RawMessage(b)
}

var privateKey *rsa.PrivateKey = nil

func oidcTestingSigner(t *testing.T) jose.Signer {
	t.Helper()
	privKey := mustGeneratePrivateKey(t)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return sig
}

func oidcTestingPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	privKey := mustGeneratePrivateKey(t)
	return &privKey.PublicKey
}

func mustGeneratePrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	if privateKey != nil {
		return privateKey
	}

	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	return privateKey
}

// normalizeMap recursively sorts []any values in a map[string]any to ensure
// deterministic test comparisons. This is necessary because JSON marshaling
// doesn't guarantee array order, and we need stable comparisons when testing
// claim merging and flattening logic.
//
// migrated from tsidp_test.go at:
// https://github.com/tailscale/tailscale/blob/3e4b0c1516819ea4/cmd/tsidp/tsidp_test.go#L50
func normalizeMap(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	normalized := make(map[string]any, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case []any:
			sorted := make([]string, len(val))
			for i, item := range val {
				sorted[i] = fmt.Sprintf("%v", item) // convert everything to string for sorting
			}
			sort.Strings(sorted)

			// convert back to []any
			sortedIface := make([]any, len(sorted))
			for i, s := range sorted {
				sortedIface[i] = s
			}
			normalized[k] = sortedIface

		default:
			normalized[k] = v
		}
	}
	return normalized
}

// marshalCapRules is a helper to convert stsCapRule slice to JSON for testing
func marshalCapRules(rules []capRule) []tailcfg.RawMessage {
	// UnmarshalCapJSON expects each rule to be a separate RawMessage
	var msgs []tailcfg.RawMessage
	for _, rule := range rules {
		data, _ := json.Marshal(rule)
		msgs = append(msgs, tailcfg.RawMessage(data))
	}
	return msgs
}
