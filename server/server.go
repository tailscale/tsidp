// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package server implements the HTTP server and handlers for the tsidp service.
package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/lazy"
	"tailscale.com/util/mak"
)

// CtxConn is a key to look up a net.Conn stored in an HTTP request's context.
// Migrated from legacy/tsidp.go:58
type CtxConn struct{}

// IDPServer handles OIDC identity provider operations
// Migrated from legacy/tsidp.go:306-323
type IDPServer struct {
	lc          *local.Client
	loopbackURL string
	hostname    string // "foo.bar.ts.net"
	serverURL   string // "https://foo.bar.ts.net"
	stateDir    string // directory for persisted state (keys, etc)
	funnel      bool
	localTSMode bool // use local tailscaled instead of tsnet
	enableSTS   bool

	lazyMux        lazy.SyncValue[*http.ServeMux]
	lazySigningKey lazy.SyncValue[*signingKey]
	lazySigner     lazy.SyncValue[jose.Signer]

	mu            sync.Mutex               // guards the fields below
	code          map[string]*AuthRequest  // keyed by random hex
	accessToken   map[string]*AuthRequest  // keyed by random hex
	refreshToken  map[string]*AuthRequest  // keyed by random hex
	funnelClients map[string]*FunnelClient // keyed by client ID

	// for bypassing application capability checks for testing
	// see issue #44
	bypassAppCapCheck bool
}

// AuthRequest represents an authorization request
type AuthRequest struct {
	// localRP is true if the request is from a relying party running on the
	// same machine as the idp server. It is mutually exclusive with rpNodeID
	// and funnelRP.
	LocalRP bool

	// rpNodeID is the NodeID of the relying party (who requested the auth, such
	// as Proxmox or Synology), not the user node who is being authenticated. It
	// is mutually exclusive with localRP and funnelRP.
	RPNodeID tailcfg.NodeID

	// funnelRP is non-nil if the request is from a relying party outside the
	// tailnet, via Tailscale Funnel. It is mutually exclusive with rpNodeID
	// and localRP.
	FunnelRP *FunnelClient

	// clientID is the "client_id" sent in the authorized request.
	ClientID string

	// nonce presented in the request.
	Nonce string

	// redirectURI is the redirect_uri presented in the request.
	RedirectURI string

	// resources are the resource URIs from RFC 8707 that the client is
	// requesting access to. These are validated at token issuance time.
	Resources []string

	// scopes are the OAuth 2.0 scopes requested by the client.
	// These are validated against supported scopes at authorization time.
	Scopes []string

	// codeChallenge is the PKCE code challenge from RFC 7636.
	// It is a derived value from the code_verifier that the client
	// will send during token exchange.
	CodeChallenge string

	// codeChallengeMethod is the method used to derive codeChallenge
	// from the code_verifier. Valid values are "plain" and "S256".
	// If empty, PKCE is not used for this request.
	CodeChallengeMethod string

	// remoteUser is the user who is being authenticated.
	RemoteUser *apitype.WhoIsResponse

	// validTill is the time until which the token is valid.
	// Authorization codes expire after 5 minutes per OAuth 2.0 best practices (RFC 6749 recommends max 10 minutes).
	ValidTill time.Time

	// IssuedAt is the time when the token was issued
	IssuedAt time.Time

	// NotValidBefore is the time before which the token is not valid yet
	NotValidBefore time.Time

	// jti is the unique identifier for the JWT token (JWT ID).
	// This is used for token introspection to return the jti claim.
	JTI string

	// Token exchange specific fields (RFC 8693)
	IsExchangedToken bool     // Indicates if this token was created via exchange
	OriginalClientID string   // The client that originally authenticated the user
	ExchangedBy      string   // The client that performed the exchange
	Audiences        []string // All intended audiences for the token

	// Delegation support (RFC 8693 act claim)
	ActorInfo *ActorClaim // For delegation scenarios
}

// ActorClaim represents the 'act' claim structure defined in RFC 8693 Section 4.1
// for delegation scenarios in token exchange.
// Migrated from legacy/tsidp.go:391-395
type ActorClaim struct {
	Subject  string      `json:"sub"`
	ClientID string      `json:"client_id,omitempty"`
	Actor    *ActorClaim `json:"act,omitempty"` // Nested for delegation chains
}

// signingKey represents a JWT signing key
// Migrated from legacy/tsidp.go:2336-2339
type signingKey struct {
	Kid uint64          `json:"kid"`
	Key *rsa.PrivateKey `json:"-"`
}

// for use with writeHTTPError() errorCode parameter
const (
	ecAccessDenied     = "access_denied"
	ecInvalidRequest   = "invalid_request"
	ecInvalidClient    = "invalid_client"
	ecInvalidGrant     = "invalid_grant"
	ecServerError      = "server_error"
	ecNotFound         = "not_found"
	ecUnsupportedGrant = "unsupported_grant_type"
)

// New creates a new IDPServer instance
func New(lc *local.Client, stateDir string, funnel, localTSMode, enableSTS bool) *IDPServer {
	return &IDPServer{
		lc:            lc,
		stateDir:      stateDir,
		funnel:        funnel,
		localTSMode:   localTSMode,
		enableSTS:     enableSTS,
		code:          make(map[string]*AuthRequest),
		accessToken:   make(map[string]*AuthRequest),
		refreshToken:  make(map[string]*AuthRequest),
		funnelClients: make(map[string]*FunnelClient),
	}
}

// SetServerURL sets the server URL
func (s *IDPServer) SetServerURL(hostname string, port int) {
	s.hostname = hostname
	if port != 443 {
		s.serverURL = fmt.Sprintf("https://%s:%d", hostname, port)
	} else {
		s.serverURL = fmt.Sprintf("https://%s", hostname)
	}
}

// ServerURL returns the server URL
func (s *IDPServer) ServerURL() string {
	return s.serverURL
}

// SetLoopbackURL sets the loopback URL
func (s *IDPServer) SetLoopbackURL(url string) {
	s.loopbackURL = url
}

// CleanupExpiredTokens removes expired tokens from memory
// Migrated from legacy/tsidp.go:2280-2299
func (s *IDPServer) CleanupExpiredTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Clean up authorization codes (they should be short-lived)
	for code, ar := range s.code {
		if now.After(ar.ValidTill) {
			delete(s.code, code)
		}
	}

	// Clean up access tokens
	for token, ar := range s.accessToken {
		if now.After(ar.ValidTill) {
			delete(s.accessToken, token)
		}
	}

	// Clean up refresh tokens (if they have an expiry)
	for token, ar := range s.refreshToken {
		if !ar.ValidTill.IsZero() && now.After(ar.ValidTill) {
			delete(s.refreshToken, token)
		}
	}
}

// ServeHTTP implements http.Handler
// Migrated from legacy/tsidp.go:689-692
func (s *IDPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.lazyMux.Get(s.newMux).ServeHTTP(w, r)
}

// newMux creates the HTTP request multiplexer
// Migrated from legacy/tsidp.go:674-687
func (s *IDPServer) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	// Register .well-known handlers
	mux.HandleFunc("/.well-known/jwks.json", s.serveJWKS)
	mux.HandleFunc("/.well-known/openid-configuration", s.serveOpenIDConfig)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.serveOAuthMetadata)

	// Register /authorize endpoint
	// Migrated from legacy/tsidp.go:679
	mux.HandleFunc("/authorize", s.serveAuthorize)

	// Register /clients/ endpoint
	// Migrated from legacy/tsidp.go:684
	mux.HandleFunc("/clients/", s.serveClients)

	// Register /token endpoint
	// Migrated from legacy/tsidp.go:681
	mux.HandleFunc("/token", s.serveToken)

	// Register /introspect endpoint
	// Migrated from legacy/tsidp.go:682
	mux.HandleFunc("/introspect", s.serveIntrospect)

	// Register /userinfo endpoint
	// Migrated from legacy/tsidp.go:680
	mux.HandleFunc("/userinfo", s.serveUserInfo)

	// Register /register endpoint for Dynamic Client Registration
	mux.HandleFunc("/register", s.addGrantAccessContext(s.serveDynamicClientRegistration))

	// Register UI handler - must be last as it handles "/"
	// Migrated from legacy/tsidp.go:685
	mux.HandleFunc("/", s.addGrantAccessContext(s.handleUI))
	return mux
}

// oidcSigner returns a JOSE signer for signing JWT tokens
// Migrated from legacy/tsidp.go:1682-1696
func (s *IDPServer) oidcSigner() (jose.Signer, error) {
	return s.lazySigner.GetErr(func() (jose.Signer, error) {
		sk, err := s.oidcPrivateKey()
		if err != nil {
			return nil, err
		}
		return jose.NewSigner(jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       sk.Key,
		}, &jose.SignerOptions{EmbedJWK: false, ExtraHeaders: map[jose.HeaderKey]any{
			jose.HeaderType: "JWT",
			"kid":           fmt.Sprint(sk.Kid),
		}})
	})
}

// oidcPrivateKey returns the private key used for signing JWT tokens
func (s *IDPServer) oidcPrivateKey() (*signingKey, error) {
	return s.lazySigningKey.GetErr(func() (*signingKey, error) {
		var sk signingKey
		keyPath := "oidc-key.json"
		if s.stateDir != "" {
			keyPath = filepath.Join(s.stateDir, "oidc-key.json")
		}
		b, err := os.ReadFile(keyPath)
		if err == nil {
			if err := json.Unmarshal(b, &sk); err == nil {
				return &sk, nil
			} else {
				slog.Warn("Error unmarshaling oidc key, recreating it", slog.Any("error", err))
			}
		}
		id, k, err := genRSAKey(2048)
		if err != nil {
			slog.Error("Error generating RSA key", slog.Any("error", err))
			return nil, fmt.Errorf("could not generate rsa key: %s", err.Error())
		}
		sk.Key = k
		sk.Kid = id
		b, err = json.Marshal(&sk)
		if err != nil {
			slog.Error("Error marshaling signing key", slog.Any("error", err))
			return nil, fmt.Errorf("could not marshal signing key, %s", err.Error())
		}
		if err := os.WriteFile(keyPath, b, 0600); err != nil {
			slog.Error("Error writing oidc key", slog.Any("error", err))
			return nil, fmt.Errorf("could not write oidc key, %s", err.Error())
		}
		return &sk, nil
	})
}

// realishEmail converts emailish addresses ending in @github or @passkey to
// a more email-like format by appending the hostname
func (s *IDPServer) realishEmail(email string) string {
	if strings.HasSuffix(email, "@github") || strings.HasSuffix(email, "@passkey") {
		return fmt.Sprintf("%s.%s", email, s.hostname)
	}

	return email
}

// genRSAKey generates an RSA key of the specified size
func genRSAKey(bits int) (kid uint64, k *rsa.PrivateKey, err error) {
	k, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	kid, err = readUint64(rand.Reader)
	return
}

// readUint64 reads a uint64 from the given reader
// Migrated from legacy/tsidp.go:2317-2329
func readUint64(r io.Reader) (uint64, error) {
	b := make([]byte, 8)
	if _, err := r.Read(b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// rsaPrivateKeyJSONWrapper wraps an RSA private key for JSON serialization
type rsaPrivateKeyJSONWrapper struct {
	Kid uint64 `json:"kid"`
	Key string `json:"key"` // PEM-encoded RSA private key
}

// MarshalJSON serializes the signing key to JSON
// Migrated from legacy/tsidp.go:2341-2351
func (sk *signingKey) MarshalJSON() ([]byte, error) {
	if sk.Key == nil {
		return nil, fmt.Errorf("signing key is nil")
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(sk.Key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	wrapper := rsaPrivateKeyJSONWrapper{
		Kid: sk.Kid,
		Key: string(pem.EncodeToMemory(pemBlock)),
	}
	return json.Marshal(wrapper)
}

// UnmarshalJSON deserializes the signing key from JSON
// Migrated from legacy/tsidp.go:2353-2375
func (sk *signingKey) UnmarshalJSON(b []byte) error {
	var wrapper rsaPrivateKeyJSONWrapper
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(wrapper.Key))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	sk.Kid = wrapper.Kid
	sk.Key = key
	return nil
}

// ServeOnLocalTailscaled starts a serve session using an already-running tailscaled
// Migrated from legacy/tsidp.go:244-304
func ServeOnLocalTailscaled(ctx context.Context, lc *local.Client, st *ipnstate.Status, dstPort uint16, shouldFunnel bool) (cleanup func(), watcherChan chan error, err error) {
	// In order to support funneling out in local tailscaled mode, we need
	// to add a serve config to forward the listeners we bound above and
	// allow those forwarders to be funneled out.
	sc, err := lc.GetServeConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get serve config: %v", err)
	}
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	// We watch the IPN bus just to get a session ID. The session expires
	// when we stop watching the bus, and that auto-deletes the foreground
	// serve/funnel configs we are creating below.
	watcher, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyNoPrivateKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("could not set up ipn bus watcher: %v", err)
	}
	defer func() {
		if err != nil {
			watcher.Close()
		}
	}()
	n, err := watcher.Next()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get initial state from ipn bus watcher: %v", err)
	}
	if n.SessionID == "" {
		err = fmt.Errorf("missing sessionID in ipn.Notify")
		return nil, nil, err
	}
	watcherChan = make(chan error)
	go func() {
		for {
			_, err = watcher.Next()
			if err != nil {
				watcherChan <- err
				return
			}
		}
	}()

	// Create a foreground serve config that gets cleaned up when tsidp
	// exits and the session ID associated with this config is invalidated.
	foregroundSc := new(ipn.ServeConfig)
	mak.Set(&sc.Foreground, n.SessionID, foregroundSc)
	serverURL := strings.TrimSuffix(st.Self.DNSName, ".")
	fmt.Printf("setting funnel for %s:%v\n", serverURL, dstPort)

	foregroundSc.SetFunnel(serverURL, dstPort, shouldFunnel)
	foregroundSc.SetWebHandler(&ipn.HTTPHandler{
		Proxy: fmt.Sprintf("https://%s", net.JoinHostPort(serverURL, strconv.Itoa(int(dstPort)))),
	}, serverURL, dstPort, "/", true, st.CurrentTailnet.MagicDNSSuffix)
	err = lc.SetServeConfig(ctx, sc)
	if err != nil {
		return nil, watcherChan, fmt.Errorf("could not set serve config: %v", err)
	}

	return func() { watcher.Close() }, watcherChan, nil
}

// writeHTTPError writes an appropriate HTTP error response based on the request's Accept header.
// It logs the error with appropriate severity level and sends either JSON or plain text response.
//
// Parameters:
//   - w: http.ResponseWriter to write the response
//   - r: *http.Request to inspect Accept header and method/path for logging
//   - statusCode: HTTP status code (e.g., 400, 401, 403, 500)
//   - errorCode: Unique error code, use constants: ecAccessDenied, ecInvalidRequest, etc.
//   - errorDescription: Human-readable error description sent in the response body
//   - err: Optional underlying error for additional logging context
func writeHTTPError(
	w http.ResponseWriter,
	r *http.Request,
	statusCode int,
	errorCode, errorDescription string,
	err error,
) {
	args := []any{
		slog.Int("status", statusCode),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("code", errorCode),
		slog.String("desc", errorDescription),
	}

	if err != nil {
		args = append(args, slog.String("error", err.Error()))
	}

	switch statusCode {
	case http.StatusForbidden, http.StatusUnauthorized:
		slog.Warn("HTTP error", args...)
	case http.StatusInternalServerError:
		slog.Error("HTTP error", args...)
	default:
		slog.Debug("HTTP error", args...)
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)

	acceptHeader := r.Header.Get("Accept")
	switch {
	case strings.Contains(acceptHeader, "application/json"):
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		json.NewEncoder(w).Encode(httpErrorResponse{
			Error:            errorCode,
			ErrorDescription: errorDescription,
		})
	default:
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		fmt.Fprintf(w, "Error %d: %s - %s", statusCode, errorCode, errorDescription)
	}
}

type httpErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
