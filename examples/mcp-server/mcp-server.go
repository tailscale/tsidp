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

	server := mcp.NewServer(&mcp.Implementation{Name: "whoa-sdk", Version: "v0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "sum", Description: "Adds two numbers"}, Sum)
	mcp.AddTool(server, &mcp.Tool{Name: "tokeninfo", Description: "Shows token info"}, TokenInfo)

	streamHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil)

	// tsidp sends an opaque token so we need to call the /introspection endpoint to validate it
	// when a token is verified it is automatically added to the request context
	// see TokenInfo(...) below for how to access the identity information.
	verifier := createVerifier(introspectionEndpoint)
	authWrappedHandler := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: ".well-known/oauth-protected-resource",
		Scopes:              []string{"email", "profile"}, /* scopes required by this server */
	})(streamHandler)

	/**
	 * Register the HTTP handlers
	 * - /mcp
	 * - /.well-known/oauth-protected-resource 	(RFC9728)
	 * - / (catch all fall through for debugging)
	 */
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("processing /mcp")

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

	http.HandleFunc("/.well-known/oauth-protected-resource", oauthProtectedResourceHandler(idpURL, "http://"+httpListenAddr))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n")

		// log the fall through ... helpful for identifying unimplemented endpoints
		fmt.Println(r.Method, r.URL.Path) // Log the request method and path
	})

	fmt.Printf("MCP server listening at %s\n", httpListenAddr)
	http.ListenAndServe(httpListenAddr, nil)
}

// createVerifier creates a token verifier function that validates tokens.
// since tsidp sends an opaque token we need to call the /introspection endpoint to validate it.
func createVerifier(introspectionEndpoint string) func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
	return func(ctx context.Context, token string, req *http.Request) (*auth.TokenInfo, error) {

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

		fmt.Println("Expirtation time", expirationTime)
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
			"resource_documentation":                "https://github.com/mostlygeek/mcp-demo",
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
