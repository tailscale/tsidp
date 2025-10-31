// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"tailscale.com/util/rands"
)

// --- Structs for Manual JSON Parsing ---
// These structs replace the types previously provided by the go-oidc and oauth2 libraries.

// ProviderMetadata holds the configuration discovered from the .well-known endpoint.
type ProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

// STSTokenResponse holds the response from a token exchange request.
type STSTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// ClientCredentials holds the client_id and client_secret after dynamic registration.
type ClientCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// TokenResponse holds the tokens returned from the token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// IDTokenHeader holds the header part of a JWT.
type IDTokenHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// IDTokenClaims holds the payload part of the ID Token JWT.
type IDTokenClaims map[string]any

// JSONWebKey represents a single public key in a JWKS.
type JSONWebKey struct {
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

// JSONWebKeySet represents a set of public keys, fetched from the jwks_uri.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// --- Configuration & Global State ---
var (
	// issuerURL is now set via a command-line flag.
	issuerURL string

	// stsEnabled determines if STS token exchange should be performed
	stsEnabled bool

	// clientID and clientSecret for static client credentials
	clientID     string
	clientSecret string

	// The local address our application will run on to handle the redirect.
	redirectHost = "http://127.0.0.1:8080"
	redirectPath = "/auth/callback"
	redirectURI  = redirectHost + redirectPath

	providerMetadata *ProviderMetadata
	clientCreds      *ClientCredentials

	// Nonce and State are used to prevent CSRF and replay attacks.
	lastState string
	lastNonce string

	// PKCE parameters for RFC 7636
	codeVerifier  string
	codeChallenge string
)

// --- Main Application Logic ---

func main() {
	// Setup and parse the flags.
	flag.StringVar(&issuerURL, "idp", "", "The issuer URL of the OpenID Connect provider (e.g., https://accounts.google.com)")
	flag.BoolVar(&stsEnabled, "sts", false, "Enable STS token exchange using urn:ietf:params:oauth:grant-type:token-exchange")
	flag.StringVar(&clientID, "client_id", "", "Static client ID (if not provided, will use dynamic client registration)")
	flag.StringVar(&clientSecret, "client_secret", "", "Static client secret (if not provided, will use dynamic client registration)")
	flag.Parse()
	if issuerURL == "" {
		fmt.Println("Error: The -idp flag is required. Please provide the issuer URL of your OIDC provider.")
		os.Exit(1)
	}

	// Validate that both client_id and client_secret are provided together or neither
	if (clientID == "") != (clientSecret == "") {
		fmt.Println("Error: Both -client_id and -client_secret must be provided together, or neither should be provided.")
		os.Exit(1)
	}

	ctx := context.Background()

	// Step 1: Fetch provider metadata from .well-known/openid-configuration
	fmt.Printf("Step 1: Fetching provider metadata from %s...\n", issuerURL)
	var err error
	providerMetadata, err = fetchProviderMetadata(ctx, issuerURL)
	if err != nil {
		fmt.Printf("Failed to fetch provider metadata: %v", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Success. Authorization Endpoint: %s\n", providerMetadata.AuthorizationEndpoint)

	// Step 2: Setup client credentials (either static or dynamic registration)
	if clientID != "" && clientSecret != "" {
		// Use static client credentials
		fmt.Println("\nStep 2: Using provided client credentials...")
		clientCreds = &ClientCredentials{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}
		fmt.Printf("✅ Success. Using Client ID: %s\n", clientCreds.ClientID)
	} else {
		// Register a new client using Dynamic Client Registration
		fmt.Println("\nStep 2: Dynamically registering a new client...")
		clientCreds, err = registerDynamicClient(ctx, providerMetadata.RegistrationEndpoint)
		if err != nil {
			fmt.Printf("Failed to register dynamic client: %v. \nNOTE: Your provider might not support Dynamic Client Registration. If so, configure client_id/secret manually using -client_id and -client_secret flags.", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Success. Registered Client ID: %s\n", clientCreds.ClientID)
	}

	// Step 3: Generate Authorization URL and attempt automated fetch.
	fmt.Println("\nStep 3: Awaiting user authorization...")
	lastState, err = generateRandomString(32)
	if err != nil {
		fmt.Printf("Failed to generate state: %v", err)
		os.Exit(1)
	}
	lastNonce, err = generateRandomString(32)
	if err != nil {
		fmt.Printf("Failed to generate nonce: %v", err)
		os.Exit(1)
	}

	// Generate PKCE parameters (RFC 7636)
	codeVerifier = rands.HexString(64)
	codeChallenge = generateCodeChallenge(codeVerifier)
	fmt.Printf("Generated PKCE parameters: code_verifier=%s..., code_challenge=%s...\n", codeVerifier[:20], codeChallenge[:20])

	authURL, err := url.Parse(providerMetadata.AuthorizationEndpoint)
	if err != nil {
		fmt.Printf("Invalid authorization endpoint URL: %v", err)
		os.Exit(1)
	}

	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("scope", "openid profile email")
	params.Add("client_id", clientCreds.ClientID)
	params.Add("redirect_uri", redirectURI)
	params.Add("state", lastState)
	params.Add("nonce", lastNonce)
	// Add PKCE parameters
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")
	authURL.RawQuery = params.Encode()
	finalAuthURL := authURL.String()

	fmt.Printf("Generated Authorization URL with state=%s, nonce=%s, and PKCE\n", lastState, lastNonce)
	fmt.Println("\nAttempting to GET the authorization URL directly...")

	// Create a client that does not follow redirects automatically.
	// This is so we can capture the Location header if a redirect is sent.
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects
		},
	}

	resp, err := httpClient.Get(finalAuthURL)
	if err != nil {
		fmt.Printf("Failed to perform GET on authorization URL: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var redirectURLStr string

	// The standard Authorization Code Flow requires user interaction. The provider will return
	// the HTML for a login page (200 OK), not an immediate redirect with a code (302 Found).
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// This block would execute if the flow could be automated without user interaction.
		// This is not expected for this OAuth flow.
		location, err := resp.Location()
		if err != nil {
			fmt.Printf("Redirect response did not have a valid Location header: %v", err)
			os.Exit(1)
		}
		fmt.Println("✅ Success: Provider sent a redirect. This is expected for the tsidp flow.")
		redirectURLStr = location.String()
	} else if resp.StatusCode == 200 {
		// This is the expected outcome. The provider is waiting for a user to log in.
		fmt.Println("⚠️ Received HTTP 200 OK. The provider has sent a login page.")
		fmt.Println("This is standard behavior. The Authorization Code Flow requires direct user interaction in a browser for authentication and consent.")
		fmt.Println("The script cannot complete the login process automatically.")
		fmt.Println("Falling back to manual authorization...")

		// Fallback to manual copy/paste
		fmt.Println("\n-------------------------------------------------------------------------")
		fmt.Println("Please open the following URL in your web browser:")
		fmt.Printf("\n%s\n\n", finalAuthURL)
		fmt.Println("After you authenticate, your browser will redirect to a URL that may show an error.")
		fmt.Println("This is expected. Please copy the ENTIRE URL from your browser's address bar.")
		fmt.Println("-------------------------------------------------------------------------")
		fmt.Print("Paste the full redirect URL here and press Enter: ")

		reader := bufio.NewReader(os.Stdin)
		redirectURLStr, err = reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Failed to read input: %v", err)
			os.Exit(1)
		}
		redirectURLStr = strings.TrimSpace(redirectURLStr)

	} else {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Unexpected response from authorization endpoint. Status: %s, Body: %s", resp.Status, string(body))
		os.Exit(1)
	}

	// Step 4: Extract params out of the pasted redirect_uri
	fmt.Println("\nStep 4: Handling redirect and extracting parameters...")
	parsedRedirectURL, err := url.Parse(redirectURLStr)
	if err != nil {
		fmt.Printf("Failed to parse the pasted redirect URL: %v", err)
		os.Exit(1)
	}

	if parsedRedirectURL.Query().Get("state") != lastState {
		fmt.Printf("❌ Error: state parameter mismatch. Expected %s, got %s", lastState, parsedRedirectURL.Query().Get("state"))
		os.Exit(1)
	}
	code := parsedRedirectURL.Query().Get("code")
	if code == "" {
		fmt.Printf("❌ Error: Authorization code not found in the redirect URL.")
		os.Exit(1)
	}
	fmt.Printf("✅ Success. Received authorization code: %s...\n", code[:20])

	// Step 5: Exchange authorization code for tokens at the token_endpoint
	fmt.Println("\nStep 5: Exchanging code for tokens...")
	tokens, err := exchangeCodeForTokens(ctx, code)
	if err != nil {
		fmt.Printf("❌ Error exchanging code: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Success. Received Access Token: %s...\n", tokens.AccessToken[:20])

	// CRITICAL STEP: Manually verify the ID Token.
	fmt.Println("\n(Critical Step) Verifying ID Token signature and claims...")
	idTokenClaims, err := verifyIDToken(ctx, tokens.IDToken, providerMetadata, clientCreds.ClientID)
	if err != nil {
		fmt.Printf("❌ Error verifying ID Token: %v\n", err)
		os.Exit(1)
	}

	iat, ok := idTokenClaims["iat"].(float64)
	if !ok {
		fmt.Printf("❌ Error: invalid 'iat' claim.: %v\n", err)
		os.Exit(1)
	}
	exp, ok := idTokenClaims["exp"].(float64)
	if !ok {
		fmt.Printf("❌ Error: invalid 'exp' claim.: %v\n", err)
		os.Exit(1)
	}
	nbf, ok := idTokenClaims["nbf"].(float64)
	if !ok {
		fmt.Printf("❌ Error: invalid 'nbf' claim.: %v\n", err)
		os.Exit(1)
	}

	if !(nbf < iat && iat < exp) {
		fmt.Printf("❌ Error: ID token expiry times invalid: nbf (%v) < iat (%v) < exp(%v)\n",
			int(nbf), int(iat), int(exp),
		)
		os.Exit(1)
	}

	if sub, ok := idTokenClaims["sub"].(string); ok {
		fmt.Printf("✅ Success. ID Token is valid. User Subject (sub): %s\n", sub)
	} else {
		fmt.Printf("✅ Success. ID Token is valid.\n")
	}

	// Step 6: Call the introspection_endpoint to get information about the token
	fmt.Println("\nStep 6: Introspecting the access token...")
	introspectionInfo, err := introspectToken(ctx, tokens.AccessToken)
	if err != nil {
		fmt.Printf("⚠️ Warning: Could not introspect token: %v\n", err)
	} else {
		fmt.Printf("✅ Success. Introspection response received.\n")
	}

	// Step 7: Call the userinfo_endpoint with the access token
	fmt.Println("\nStep 7: Calling userinfo endpoint...")
	userInfo, err := fetchUserInfo(ctx, tokens.AccessToken)
	if err != nil {
		fmt.Printf("❌ Error fetching user info: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Success. UserInfo response received.\n")

	// Step 8: Perform STS token exchange if -sts flag is enabled
	if stsEnabled {
		fmt.Println("\nStep 8: Performing STS token exchange...")
		stsToken, err := performTokenExchange(ctx, tokens.AccessToken)
		if err != nil {
			fmt.Printf("❌ Error performing token exchange: %v\n", err)
		} else {
			fmt.Printf("✅ Success. Received exchanged token: %s...\n", stsToken.AccessToken[:20])
			fmt.Println("\n--- STS Token Exchange Response ---")
			fmt.Println(prettyPrint(stsToken))
		}
	}

	// Display final results to the console
	fmt.Println("\n---------------------- OIDC FLOW COMPLETE ----------------------")
	fmt.Println("\n✅ All steps completed successfully!")
	fmt.Println("\n--- ID Token Claims ---")
	fmt.Println(prettyPrint(idTokenClaims))
	fmt.Println("\n--- Introspection Response ---")
	fmt.Println(prettyPrintJSON(introspectionInfo))
	fmt.Println("\n--- UserInfo Response ---")
	fmt.Println(prettyPrintJSON(userInfo))
	fmt.Println("--------------------------------------------------------------")
}

// --- OIDC/OAuth2 Flow Functions (Manual HTTP) ---

// Step 1: Fetches and stores the provider's configuration.
func fetchProviderMetadata(ctx context.Context, issuer string) (*ProviderMetadata, error) {
	wellKnownURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata request failed with status: %s", resp.Status)
	}

	var meta ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// Step 2: Dynamically registers this application as a new client.
func registerDynamicClient(ctx context.Context, registrationURL string) (*ClientCredentials, error) {
	if registrationURL == "" {
		return nil, fmt.Errorf("provider does not support dynamic client registration (no registration_endpoint)")
	}

	regReq := map[string]interface{}{
		"client_name":                "OIDC Verifier Tool (Manual)",
		"redirect_uris":              []string{redirectURI},
		"response_types":             []string{"code"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "client_secret_post",
	}

	reqBody, err := json.Marshal(regReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", registrationURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	var creds ClientCredentials
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

// Step 5: Exchanges the authorization code for tokens.
func exchangeCodeForTokens(ctx context.Context, code string) (*TokenResponse, error) {
	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	params.Add("redirect_uri", redirectURI)
	params.Add("client_id", clientCreds.ClientID)
	params.Add("client_secret", clientCreds.ClientSecret)
	// Add PKCE code_verifier
	params.Add("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, "POST", providerMetadata.TokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokens TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}

// verifyIDToken manually parses and validates a JWT ID token.
func verifyIDToken(ctx context.Context, rawToken string, meta *ProviderMetadata, clientID string) (IDTokenClaims, error) {
	// 1. Split the token into 3 parts: header, payload, signature
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format: must have 3 parts")
	}

	// 2. Decode header and payload
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token header: %w", err)
	}
	var header IDTokenHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token header: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}
	var claims IDTokenClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token claims: %w", err)
	}

	// 3. Fetch the public keys (JWKS) from the provider
	keySet, err := fetchJWKS(ctx, meta.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// 4. Find the correct key and verify the signature
	err = verifySignature(parts[0]+"."+parts[1], parts[2], header.KeyID, keySet)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	fmt.Println("✅ Signature is valid.")

	// 5. Validate the claims
	issuer, _ := claims["iss"].(string)
	if issuer != meta.Issuer {
		return nil, fmt.Errorf("issuer mismatch: expected %s, got %s", meta.Issuer, issuer)
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("exp claim missing or invalid")
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return nil, errors.New("token has expired")
	}

	// Handle audience as either string or array
	audMatch := false
	switch aud := claims["aud"].(type) {
	case string:
		audMatch = (aud == clientID)
	case []interface{}:
		for _, a := range aud {
			if audStr, ok := a.(string); ok && audStr == clientID {
				audMatch = true
				break
			}
		}
	}
	if !audMatch {
		return nil, fmt.Errorf("audience mismatch: token not intended for this client")
	}

	nonce, _ := claims["nonce"].(string)
	if nonce != lastNonce {
		return nil, fmt.Errorf("nonce mismatch: expected %s, got %s", lastNonce, nonce)
	}
	fmt.Println("✅ All claims are valid.")

	return claims, nil
}

func fetchJWKS(ctx context.Context, jwksURI string) (*JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks request failed with status: %s", resp.Status)
	}

	var keySet JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
		return nil, err
	}
	return &keySet, nil
}

func verifySignature(signingString, signature string, keyID string, keySet *JSONWebKeySet) error {
	// Find the key in the set that matches the token's key ID.
	var jwk *JSONWebKey
	for i := range keySet.Keys {
		if keySet.Keys[i].KeyID == keyID {
			jwk = &keySet.Keys[i]
			break
		}
	}
	if jwk == nil {
		return fmt.Errorf("public key with kid '%s' not found in JWKS", keyID)
	}
	if jwk.KeyType != "RSA" {
		return fmt.Errorf("unsupported key type: %s", jwk.KeyType)
	}

	// Decode the modulus (n) and exponent (e) from Base64URL
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
	if err != nil {
		return err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
	if err != nil {
		return err
	}

	// Construct the RSA public key
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	// Decode the signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	// Hash the signing string
	hasher := sha256.New()
	hasher.Write([]byte(signingString))
	hashed := hasher.Sum(nil)

	// Verify the signature
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed, sigBytes)
}

// Step 6: Calls the introspection endpoint.
func introspectToken(ctx context.Context, accessToken string) (string, error) {
	if providerMetadata.IntrospectionEndpoint == "" {
		return "", errors.New("provider does not support token introspection")
	}

	data := url.Values{}
	data.Set("token", accessToken)
	data.Set("client_id", clientCreds.ClientID)
	data.Set("client_secret", clientCreds.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", providerMetadata.IntrospectionEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("introspection request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// Step 7: Fetches user information from the userinfo endpoint.
func fetchUserInfo(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", providerMetadata.UserInfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo request failed with status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// --- Utility Functions ---

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generateCodeChallenge generates a PKCE code challenge using S256 method.
func generateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func prettyPrint(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error pretty printing: %v", err)
	}
	return string(data)
}

func prettyPrintJSON(jsonStr string) string {
	var v interface{}
	if err := json.Unmarshal([]byte(jsonStr), &v); err != nil {
		return jsonStr // Not valid JSON, return as is
	}
	return prettyPrint(v)
}

// performTokenExchange performs an OAuth 2.0 Token Exchange as per RFC 8693.
func performTokenExchange(ctx context.Context, subjectToken string) (*STSTokenResponse, error) {
	params := url.Values{}
	params.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	params.Add("subject_token", subjectToken)
	params.Add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	params.Add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	params.Add("audience", clientCreds.ClientID)
	params.Add("client_id", clientCreds.ClientID)
	params.Add("client_secret", clientCreds.ClientSecret)
	params.Add("scope", "openid profile")

	req, err := http.NewRequestWithContext(ctx, "POST", providerMetadata.TokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var stsResponse STSTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&stsResponse); err != nil {
		return nil, err
	}

	// Validate that the returned token has the required scopes
	if !validateScopes(stsResponse.Scope, []string{"openid", "email", "profile"}) {
		return nil, fmt.Errorf("token exchange returned insufficient scopes: got %s", stsResponse.Scope)
	}

	return &stsResponse, nil
}

// Helper function to validate scopes
func validateScopes(returnedScope string, requiredScopes []string) bool {
	returnedScopes := strings.Fields(returnedScope)
	for _, required := range requiredScopes {
		found := false
		for _, returned := range returnedScopes {
			if returned == required {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
