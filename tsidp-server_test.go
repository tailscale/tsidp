// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
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
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
