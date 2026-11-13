// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadAuthKeyFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{name: "plain key", content: "tskey-auth-abc123", want: "tskey-auth-abc123"},
		{name: "trailing newline", content: "tskey-auth-abc123\n", want: "tskey-auth-abc123"},
		{name: "surrounding whitespace", content: "  tskey-auth-abc123  \n", want: "tskey-auth-abc123"},
		{name: "empty file", content: "", wantErr: true},
		{name: "whitespace only", content: "   \n\t", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authkey")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := readAuthKeyFile(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("readAuthKeyFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("readAuthKeyFile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadAuthKeyFileMissing(t *testing.T) {
	_, err := readAuthKeyFile(filepath.Join(t.TempDir(), "does-not-exist"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestResolveAuthKeyFile(t *testing.T) {
	t.Run("file missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "does-not-exist")

		key, err := resolveAuthKeyFile(path)
		if err != nil || key != "" {
			t.Fatalf("got key=%q err=%v, want key=\"\" err=nil", key, err)
		}
	})

	t.Run("file empty", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authkey")
		mustWriteFile(t, path, "")

		key, err := resolveAuthKeyFile(path)
		if err == nil || key != "" {
			t.Fatalf("got key=%q err=%v, want key=\"\" err!=nil", key, err)
		}
	})

	t.Run("file valid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authkey")
		mustWriteFile(t, path, "tskey-auth-file\n")

		key, err := resolveAuthKeyFile(path)
		if err != nil || key != "tskey-auth-file" {
			t.Fatalf("got key=%q err=%v, want key=%q err=nil", key, err, "tskey-auth-file")
		}
	})
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParseLoginServer(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty uses default", in: "", want: ""},
		{name: "whitespace only uses default", in: "   ", want: ""},
		{name: "https", in: "https://headscale.example.com", want: "https://headscale.example.com"},
		{name: "http", in: "http://headscale.example.com:8080", want: "http://headscale.example.com:8080"},
		{name: "trailing slash removed", in: "https://headscale.example.com/", want: "https://headscale.example.com"},
		{name: "surrounding whitespace", in: "  https://headscale.example.com  ", want: "https://headscale.example.com"},
		{name: "with path", in: "https://example.com/headscale", want: "https://example.com/headscale"},
		{name: "missing scheme", in: "headscale.example.com", wantErr: true},
		{name: "unsupported scheme", in: "ftp://headscale.example.com", wantErr: true},
		{name: "missing host", in: "https://", wantErr: true},
		{name: "unparsable", in: "http://[::1", wantErr: true},
		{name: "userinfo", in: "https://user:secret@hs.example.com", wantErr: true},
		{name: "username only", in: "https://user@hs.example.com", wantErr: true},
		{name: "port without host", in: "https://:443", wantErr: true},
		{name: "query", in: "https://hs.example.com?x=1", wantErr: true},
		{name: "empty query", in: "https://hs.example.com?", wantErr: true},
		{name: "fragment", in: "https://hs.example.com/#f", wantErr: true},
		{name: "empty fragment", in: "https://hs.example.com#", wantErr: true},
		{name: "opaque", in: "https:hs.example.com", wantErr: true},
		{name: "uppercase scheme", in: "HTTPS://Hs.example.com", want: "https://Hs.example.com"},
		{name: "multiple trailing slashes", in: "https://hs.example.com//", want: "https://hs.example.com"},
		{name: "path with trailing slashes", in: "https://example.com/headscale///", want: "https://example.com/headscale"},
		{name: "ipv6 with port", in: "http://[::1]:8080", want: "http://[::1]:8080"},
		{name: "opaque with credentials", in: "https:user:secret@hs.example.com", wantErr: true},
		{name: "single slash with credentials", in: "http:/user:secret@hs.example.com", wantErr: true},
		{name: "credentials without scheme", in: "user:secret@hs.example.com", wantErr: true},
		{name: "secret in query", in: "https://hs.example.com?token=secret", wantErr: true},
		{name: "secret in port", in: "https://hs.example.com:secret", wantErr: true},
		{name: "secret in fragment", in: "https://hs.example.com#secret", wantErr: true},
		{name: "secret in unsupported scheme", in: "ftp://secret.example.com", wantErr: true},
		{name: "secret in unparsable host", in: "http://[secret", wantErr: true},
		{name: "secret with port-only host", in: "https://:443/secret", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLoginServer(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseLoginServer(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			// Errors are logged, so they must never echo any part of the input.
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Errorf("parseLoginServer(%q) error %q leaks input", tt.in, err)
			}
			if err == nil && got != tt.want {
				t.Errorf("parseLoginServer(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
