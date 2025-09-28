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
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tailscale/tsidp/server"

	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"

	"tailscale.com/tsnet"
	"tailscale.com/version"
)

// Command line flags
// Migrated from legacy/tsidp.go:64-73
var (
	flagPort               = flag.Int("port", 443, "port to listen on")
	flagLocalPort          = flag.Int("local-port", -1, "allow requests from localhost")
	flagUseLocalTailscaled = flag.Bool("use-local-tailscaled", false, "use local tailscaled instead of tsnet")
	flagFunnel             = flag.Bool("funnel", false, "use Tailscale Funnel to make tsidp available on the public internet")
	flagHostname           = flag.String("hostname", "idp", "tsnet hostname to use instead of idp")
	flagDir                = flag.String("dir", "", "tsnet state directory; a default one will be created if not provided")
	flagEnableSTS          = flag.Bool("enable-sts", false, "enable OIDC STS token exchange support")

	// application logging levels
	flagLogLevel = flag.String("log", "info", "log levels: debug, info, warn, error")

	// extended debugging information
	flagDebugAllRequests = flag.Bool("debug-all-requests", false, "capture and print all HTTP requests and responses")
	flagDebugTSNet       = flag.Bool("debug-tsnet", false, "enable tsnet.Server logging")
)

// main initializes and starts the tsidp server
// Migrated from legacy/tsidp.go:75-239
func main() {
	flag.Parse()
	ctx := context.Background()
	if !envknob.UseWIPCode() {
		slog.Error("cmd/tsidp is a work in progress and has not been security reviewed;\nits use requires TAILSCALE_USE_WIP_CODE=1 be set in the environment for now.")
		os.Exit(1)
	}

	switch *flagLogLevel {
	case "debug":
		slog.SetLogLoggerLevel(slog.LevelDebug)
	case "info":
		slog.SetLogLoggerLevel(slog.LevelInfo)
	case "warn":
		slog.SetLogLoggerLevel(slog.LevelWarn)
	case "error":
		slog.SetLogLoggerLevel(slog.LevelError)
	default:
		slog.Error("unknown log level", slog.String("level", *flagLogLevel))
		os.Exit(1)
	}

	var (
		lc          *local.Client
		st          *ipnstate.Status
		err         error
		watcherChan chan error
		cleanup     func()

		lns []net.Listener
	)
	if *flagUseLocalTailscaled {
		lc = &local.Client{}
		st, err = lc.StatusWithoutPeers(ctx)
		if err != nil {
			slog.Error("getting local.Client status", slog.Any("error", err))
			os.Exit(1)
		}
		portStr := fmt.Sprint(*flagPort)
		anySuccess := false
		for _, ip := range st.TailscaleIPs {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), portStr))
			if err != nil {
				slog.Warn("net.Listen failed", slog.String("ip", ip.String()), slog.Any("error", err))
				continue
			}
			anySuccess = true
			ln = tls.NewListener(ln, &tls.Config{
				GetCertificate: lc.GetCertificate,
			})
			lns = append(lns, ln)
		}
		if !anySuccess {
			slog.Error("failed to listen on any ip", slog.Any("ips", st.TailscaleIPs))
			os.Exit(1)
		}

		// tailscaled needs to be setting an HTTP header for funneled requests
		// that older versions don't provide.
		// TODO(naman): is this the correct check?
		if *flagFunnel && !version.AtLeast(st.Version, "1.71.0") {
			slog.Error("Local tailscaled not new enough to support -funnel. Update Tailscale or use tsnet mode.")
			os.Exit(1)
		}
		cleanup, watcherChan, err = server.ServeOnLocalTailscaled(ctx, lc, st, uint16(*flagPort), *flagFunnel)
		if err != nil {
			slog.Error("could not serve on local tailscaled", slog.Any("error", err))
			os.Exit(1)
		}
		defer cleanup()
	} else {
		hostinfo.SetApp("tsidp")
		ts := &tsnet.Server{
			Hostname: *flagHostname,
			Dir:      *flagDir,
		}
		if *flagDebugTSNet {
			ts.Logf = func(format string, args ...any) {
				cur := slog.SetLogLoggerLevel(slog.LevelDebug) // force debug if this option is on
				slog.Debug(fmt.Sprintf(format, args...))
				slog.SetLogLoggerLevel(cur)
			}
		}
		st, err = ts.Up(ctx)
		if err != nil {
			slog.Error("failed to start tsnet server", slog.Any("error", err))
			os.Exit(1)
		}
		lc, err = ts.LocalClient()
		if err != nil {
			slog.Error("failed to get local client", slog.Any("error", err))
			os.Exit(1)
		}
		var ln net.Listener
		if *flagFunnel {
			if err := ipn.CheckFunnelAccess(uint16(*flagPort), st.Self); err != nil {
				slog.Error("funnel access denied", slog.Any("error", err))
				os.Exit(1)
			}
			ln, err = ts.ListenFunnel("tcp", fmt.Sprintf(":%d", *flagPort))
		} else {
			ln, err = ts.ListenTLS("tcp", fmt.Sprintf(":%d", *flagPort))
		}

		if err != nil {
			slog.Error("failed to listen", slog.Any("error", err))
			os.Exit(1)
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
		slog.Error("could not load funnel clients", slog.Any("error", err))
		os.Exit(1)
	}

	slog.Info("tsidp server started", slog.String("server_url", srv.ServerURL()))

	if *flagLocalPort != -1 {
		loopbackURL := fmt.Sprintf("http://localhost:%d", *flagLocalPort)
		slog.Info("Also running tsidp at loopback", slog.String("loopback_url", loopbackURL))
		srv.SetLoopbackURL(loopbackURL)
		ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *flagLocalPort))
		if err != nil {
			slog.Error("failed to listen on loopback", slog.Any("error", err))
			os.Exit(1)
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
				slog.Debug("Cleaned up expired tokens")
			case <-cleanupCtx.Done():
				return
			}
		}
	}()

	var srvHandler http.Handler = srv
	if *flagDebugAllRequests {
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
		slog.Info("interrupt, exiting")
		return
	case <-watcherChan:
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			slog.Info("watcher closed, exiting")
			return
		}
		slog.Error("watcher error", slog.Any("error", err))
		os.Exit(1)
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
