// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsidp command is an OpenID Connect Identity Provider server.
//
// See https://github.com/tailscale/tailscale/issues/10263 for background.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/tailscale/tsidp/server"

	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"

	"tailscale.com/tsnet"
	"tailscale.com/version"
)

// main initializes and starts the tsidp server
// Migrated from legacy/tsidp.go:75-239
func main() {
	fs := ff.NewFlagSet("tsidp")
	// flag vars
	var (
		flagVerbose            = fs.Bool('v', "verbose", "be verbose")
		flagPort               = fs.Int('p', "port", 443, "port to listen on")
		flagLocalPort          = fs.IntLong("local-port", -1, "allow requests from localhost")
		flagUseLocalTailscaled = fs.BoolLong("use-local-tailscaled", "use local tailscaled instead of tsnet")
		flagFunnel             = fs.BoolLong("funnel", "use Tailscale Funnel to make tsidp available on the public internet")
		flagHostname           = fs.StringLong("hostname", "idp", "tsnet hostname to use instead of idp")
		flagDir                = fs.StringLong("dir", "", "tsnet state directory; a default one will be created if not provided")
		flagEnableSTS          = fs.BoolLong("enable-sts", "enable OIDC STS token exchange support")
		flagEnableDebug        = fs.BoolLong("enable-debug", "enable debug printing of requests to the server")
	)
	// general vars
	var (
		lc          *local.Client
		st          *ipnstate.Status
		err         error
		watcherChan chan error
		cleanup     func()

		lns []net.Listener
	)

	err = ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("TSIDP_FLAG"), // try `env TSIDP_FLAG_PORT=8080 tsidp`
	)
	switch {
	case errors.Is(err, ff.ErrHelp):
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
		fmt.Fprintf(os.Stderr, "\nEnvironment variables (TSIDP_FLAG_ prefix):\n")
		fmt.Fprintf(os.Stderr, "  TSIDP_FLAG_VERBOSE        same as --verbose\n")
		fmt.Fprintf(os.Stderr, "  TSIDP_FLAG_PORT           same as --port\n")
		fmt.Fprintf(os.Stderr, "  TSIDP_FLAG_LOCAL_PORT     same as --local-port\n")
		fmt.Fprintf(os.Stderr, "  TSIDP_FLAG_USE_LOCAL_TAILSCALED  same as --use-local-tailscaled\n")
		fmt.Fprintf(os.Stderr, "  TSIDP_FLAG_FUNNEL         same as --funnel\n")
		fmt.Fprintf(os.Stderr, "  TSIDP_FLAG_HOSTNAME       same as --hostname\n")
		fmt.Fprintf(os.Stderr, "  TSIDP_FLAG_DIR            same as --dir\n")
		fmt.Fprintf(os.Stderr, "  TSIDP_FLAG_ENABLE_STS     same as --enable-sts\n")
		fmt.Fprintf(os.Stderr, "  TSIDP_FLAG_ENABLE_DEBUG   same as --enable-debug\n")
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if !envknob.UseWIPCode() {
		log.Fatal("cmd/tsidp is a work in progress and has not been security reviewed;\nits use requires TAILSCALE_USE_WIP_CODE=1 be set in the environment for now.")
	}

	if *flagUseLocalTailscaled {
		lc = &local.Client{}
		st, err = lc.StatusWithoutPeers(ctx)
		if err != nil {
			log.Fatalf("getting status: %v", err)
		}
		portStr := fmt.Sprint(*flagPort)
		anySuccess := false
		for _, ip := range st.TailscaleIPs {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), portStr))
			if err != nil {
				log.Printf("failed to listen on %v: %v", ip, err)
				continue
			}
			anySuccess = true
			ln = tls.NewListener(ln, &tls.Config{
				GetCertificate: lc.GetCertificate,
			})
			lns = append(lns, ln)
		}
		if !anySuccess {
			log.Fatalf("failed to listen on any of %v", st.TailscaleIPs)
		}

		// tailscaled needs to be setting an HTTP header for funneled requests
		// that older versions don't provide.
		// TODO(naman): is this the correct check?
		if *flagFunnel && !version.AtLeast(st.Version, "1.71.0") {
			log.Fatalf("Local tailscaled not new enough to support -funnel. Update Tailscale or use tsnet mode.")
		}
		cleanup, watcherChan, err = server.ServeOnLocalTailscaled(ctx, lc, st, uint16(*flagPort), *flagFunnel)
		if err != nil {
			log.Fatalf("could not serve on local tailscaled: %v", err)
		}
		defer cleanup()
	} else {
		hostinfo.SetApp("tsidp")
		ts := &tsnet.Server{
			Hostname: *flagHostname,
			Dir:      *flagDir,
		}
		if *flagVerbose {
			ts.Logf = log.Printf
		}
		st, err = ts.Up(ctx)
		if err != nil {
			log.Fatal(err)
		}
		lc, err = ts.LocalClient()
		if err != nil {
			log.Fatalf("getting local client: %v", err)
		}
		var ln net.Listener
		if *flagFunnel {
			if err := ipn.CheckFunnelAccess(uint16(*flagPort), st.Self); err != nil {
				log.Fatalf("%v", err)
			}
			ln, err = ts.ListenFunnel("tcp", fmt.Sprintf(":%d", *flagPort))
		} else {
			ln, err = ts.ListenTLS("tcp", fmt.Sprintf(":%d", *flagPort))
		}
		if err != nil {
			log.Fatal(err)
		}
		lns = append(lns, ln)
	}

	srv := server.New(
		lc,
		*flagDir,
		*flagFunnel,
		*flagUseLocalTailscaled,
		*flagEnableSTS,
	)

	if *flagPort != 443 {
		srv.SetServerURL(fmt.Sprintf("https://%s:%d", strings.TrimSuffix(st.Self.DNSName, "."), *flagPort))
	} else {
		srv.SetServerURL(fmt.Sprintf("https://%s", strings.TrimSuffix(st.Self.DNSName, ".")))
	}

	// Load funnel clients from disk if they exist, regardless of whether funnel is enabled
	// This ensures OIDC clients persist across restarts
	if err := srv.LoadFunnelClients(); err != nil {
		log.Fatalf("could not load funnel clients: %v", err)
	}

	log.Printf("Running tsidp at %s ...", srv.ServerURL())

	if *flagLocalPort != -1 {
		loopbackURL := fmt.Sprintf("http://localhost:%d", *flagLocalPort)
		log.Printf("Also running tsidp at %s ...", loopbackURL)
		srv.SetLoopbackURL(loopbackURL)
		ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *flagLocalPort))
		if err != nil {
			log.Fatal(err)
		}
		lns = append(lns, ln)
	}

	// Start token cleanup routine
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	defer cleanupCancel()

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				srv.CleanupExpiredTokens()
				if *flagVerbose {
					log.Printf("Cleaned up expired tokens")
				}
			case <-cleanupCtx.Done():
				return
			}
		}
	}()

	var srvHandler http.Handler = srv
	if *flagEnableDebug {
		srvHandler = debugPrintRequest(srv) // Wrap the server with debug
	}

	for _, ln := range lns {
		httpServer := http.Server{

			// TODO: THIS IS ONLY FOR DEBUGGING
			Handler: srvHandler,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, server.CtxConn{}, c)
			},
		}
		go httpServer.Serve(ln)
	}
	// need to catch os.Interrupt, otherwise deferred cleanup code doesn't run
	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt)
	select {
	case <-exitChan:
		log.Printf("interrupt, exiting")
		return
	case <-watcherChan:
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			log.Printf("watcher closed, exiting")
			return
		}
		log.Fatalf("watcher error: %v", err)
		return
	}
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

		// Print query parameters
		if len(r.URL.Query()) > 0 {
			fmt.Printf("[DEBUG REQUEST] Query Parameters:\n")
			for name, values := range r.URL.Query() {
				for _, value := range values {
					fmt.Printf("[DEBUG REQUEST]   %s: %s\n", name, value)
				}
			}
		}

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
