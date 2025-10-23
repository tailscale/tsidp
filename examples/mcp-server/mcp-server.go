package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {

	var tsidpFlag string
	flag.StringVar(&tsidpFlag, "tsidp", "", "tsidp hostname (required), eg: mcp-demo-idp.ts00001.ts.net")

	var httpListenAddr string
	flag.StringVar(&httpListenAddr, "http", "localhost:9933", "http listen address")

	var oauthResource string
	flag.StringVar(&oauthResource, "resource", "", "sets resource URL, otherwise defaults to http listener value")

	var enableDebug bool
	flag.BoolVar(&enableDebug, "enable-debug", false, "enable debug mode (default: false)")

	flag.Parse()

	if tsidpFlag == "" {
		fmt.Println("Error: -tsidp flag is required")
		os.Exit(1)
	}

	idpURL := "https://" + tsidpFlag
	fmt.Println("tsidp URL: ", idpURL)

	// fetch the .well-known/oauth-authorization-server endpoint to get the introspection_endpoint
	introspectionEndpoint, err := fetchIntrospectionEndpoint(idpURL)
	if err != nil {
		fmt.Printf("Error fetching introspection_endpoint: %v", err)
		os.Exit(1)
	}

	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "whoa-sdk", Version: "v0.0.1"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "sum", Description: "Adds two numbers"}, Sum)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "tokeninfo", Description: "Shows token info"}, TokenInfo)

	streamHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return mcpServer
	}, nil)

	if oauthResource == "" {
		oauthResource = "http://" + httpListenAddr
	}

	// tsidp sends an opaque token so we need to call the /introspection endpoint to validate it
	// when a token is verified it is automatically added to the request context
	// see TokenInfo(...) below for how to access the identity information.
	verifier := createVerifier(introspectionEndpoint)
	authWrappedHandler := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: fmt.Sprintf("%s/%s", oauthResource, ".well-known/oauth-protected-resource"),
		Scopes:              []string{"email", "profile"}, /* scopes required by this server */
	})(streamHandler)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", oauthProtectedResourceHandler(idpURL, oauthResource))

	/**
	 * Register the HTTP handlers
	 * - /mcp
	 * - /.well-known/oauth-protected-resource 	(RFC9728)
	 * - / (catch all fall through for debugging)
	 */
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Handling MCP: " + r.Method)
		if r.Method == "OPTIONS" {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Allow-Headers", "*")
			h.Set("Access-Control-Allow-Method", "GET, POST, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		authWrappedHandler.ServeHTTP(w, r)
	})

	var srvHandler http.Handler = mux
	if enableDebug {
		srvHandler = debugPrintRequest(mux)
	}

	fmt.Printf("MCP server listening at %s\n", httpListenAddr)
	httpServer := &http.Server{
		Addr:    httpListenAddr,
		Handler: srvHandler,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// createVerifier creates a token verifier function that validates tokens.
// since tsidp sends an opaque token we need to call the /introspection endpoint to validate it.
func createVerifier(introspectionEndpoint string) func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
	return func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {

		fmt.Println("IN Verifier, the token: ", token)

		// make an HTTP POST with application/x-www-formencoded-body to tsidp
		data := url.Values{}
		data.Set("token", token)
		req, err := http.NewRequestWithContext(ctx, "POST", introspectionEndpoint, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, fmt.Errorf("creating request to introspection endpoint: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("making request to introspection endpoint: %w", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}

		// decode the response introspection api response
		var result map[string]any
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(&result); err != nil {
			return nil, fmt.Errorf("decoding introspection response: %w", err)
		}

		if result["active"] == false {
			return nil, fmt.Errorf("token is not active") // Return error
		}

		// extract expiration (exp) and convert it into time.Date and put the rest into "Extra"
		expiration, ok := result["exp"].(float64)
		if !ok {
			return nil, fmt.Errorf("exp field missing or not a number: %v", result["exp"])
		}
		expirationTime := time.Unix(int64(expiration), 0)

		fmt.Println("Expiration time", expirationTime)
		return &auth.TokenInfo{
			Scopes: []string{"email", "profile"},
			// Expiration is far, far in the future.
			Expiration: expirationTime,
			Extra:      result,
		}, nil
	}
}

// Implement RFC9728 - OAuth 2.0 Protected Resource Metadata endpoint
func oauthProtectedResourceHandler(authServerUrl string, resourceURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method == "OPTIONS" {
			log.Println("OPTIONS .well-known/oauth-protected-resource")
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Allow-Headers", "*")
			h.Set("Access-Control-Allow-Method", "GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)

			return
		}

		log.Println("GET .well-known/oauth-protected-resource")
		// OAuth Protected Resource Discovery metadata
		// This follows the OAuth 2.0 Protected Resource Metadata specification
		metadata := map[string]interface{}{
			"resource":                              resourceURL,
			"authorization_servers":                 []string{authServerUrl},
			"bearer_methods_supported":              []string{"header"},
			"resource_documentation":                "https://github.com/tailscale/tsidp/examples/mcp-server",
			"resource_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"email", "profile"}, // match tsidp/.well-known/openid-configuration
		}

		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Method", "GET, OPTIONS")
		// allow all to prevent errors from client sending their own bespoke headers
		// and having the server reject the request.
		h.Set("Access-Control-Allow-Headers", "*")

		json.NewEncoder(w).Encode(metadata)
	}
}

func fetchIntrospectionEndpoint(idpURL string) (string, error) {
	metaURL := idpURL + "/.well-known/oauth-authorization-server"
	fmt.Println("Fetching: ", metaURL)

	// Create HTTP client with timeout so it doesn't hang forever if tsidp is not found
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(metaURL)
	if err != nil {
		return "", fmt.Errorf("error fetching .well-known/oauth-authorization-server: %w", err)
	}
	defer resp.Body.Close()

	// json decode the response body into a map
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding .well-known/oauth-authorization-server: %w", err)
	}

	if url, ok := result["introspection_endpoint"].(string); ok {
		return url, nil
	} else {
		return "", fmt.Errorf("introspection_endpoint not found at %s", metaURL)
	}
}

/**
 * Tools for MCP server
 */
func TokenInfo(ctx context.Context, req *mcp.CallToolRequest, _ struct{} /* no args */) (*mcp.CallToolResult, any, error) {
	token := req.Extra.TokenInfo
	scopes := "none"
	if len(token.Scopes) > 0 {
		scopes = fmt.Sprintf("%v", token.Scopes)
	}

	// Format expiration
	expiration := token.Expiration.Format("2006/01/02 15:04:05")

	// Build the tokenInfo string
	tokenInfo := fmt.Sprintf("Scopes: %s\nExpiration: %s\nExtra:", scopes, expiration)

	// Add extra fields
	for key, value := range token.Extra {
		tokenInfo += fmt.Sprintf("\n- %s: %v", key, value)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: tokenInfo},
		},
	}, nil, nil
}

type SumParams struct {
	X int `json:"x"`
	Y int `json:"y"`
}

// Sum just adds two numbers to test tool calling.
func Sum(ctx context.Context, req *mcp.CallToolRequest, args SumParams) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("%d", args.X+args.Y)},
		},
	}, nil, nil
}

func debugPrintRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and store the request body
		var requestBody []byte
		if r.Body != nil {
			requestBody, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(requestBody)) // Restore body for downstream handlers
		}

		// Print request details
		fmt.Printf("[DEBUG REQUEST] %s %s %s\n", r.Method, r.URL.Path, r.Proto)
		fmt.Printf("[DEBUG REQUEST] Host: %s\n", r.Host)
		fmt.Printf("[DEBUG REQUEST] RemoteAddr: %s\n", r.RemoteAddr)
		fmt.Printf("[DEBUG REQUEST] User-Agent: %s\n", r.UserAgent())

		// Print request headers
		fmt.Printf("[DEBUG REQUEST] Headers:\n")
		for name, values := range r.Header {
			for _, value := range values {
				fmt.Printf("[DEBUG REQUEST]   %s: %s\n", name, value)
			}
		}

		// Print request body if present
		if len(requestBody) > 0 {
			fmt.Printf("[DEBUG REQUEST] Body:\n%s\n", string(requestBody))
		} else {
			fmt.Printf("[DEBUG REQUEST] Body: (empty)\n")
		}

		fmt.Println("[DEBUG REQUEST] ---")

		// Create a custom ResponseWriter to capture status code and body
		rw := &responseWrapper{
			ResponseWriter: w,
			statusCode:     200, // Default status code
			body:           &bytes.Buffer{},
		}

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Print response status code
		fmt.Printf("[DEBUG RESPONSE] Status: %d %s\n", rw.statusCode, http.StatusText(rw.statusCode))

		// Print response headers (captured from the original ResponseWriter)
		fmt.Printf("[DEBUG RESPONSE] Headers:\n")
		for name, values := range w.Header() {
			for _, value := range values {
				fmt.Printf("[DEBUG RESPONSE]   %s: %s\n", name, value)
			}
		}

		// Print response body
		responseBody := rw.body.Bytes()
		if len(responseBody) > 0 {
			fmt.Printf("[DEBUG RESPONSE] Body:\n%s\n", string(responseBody))
		} else {
			fmt.Printf("[DEBUG RESPONSE] Body: (empty)\n")
		}

		fmt.Println("[DEBUG RESPONSE] ---")
	})
}

type responseWrapper struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWrapper) Write(b []byte) (int, error) {
	// Capture the response body
	if rw.body != nil {
		rw.body.Write(b)
	}

	// Write to the original response writer
	return rw.ResponseWriter.Write(b)
}
