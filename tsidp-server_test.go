// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"path/filepath"
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
