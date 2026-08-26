// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import "runtime/debug"

// version is set at build time via ldflags:
// go build -ldflags "-X github.com/tailscale/tsidp/server.version=v1.2.3"
var version string

// GetVersion returns the version string for tsidp.
// Priority: ldflag-injected tag > VCS short hash > "dev".
func GetVersion() string { return cachedVersion }

var cachedVersion = func() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				if len(s.Value) > 7 {
					return s.Value[:7]
				}
				return s.Value
			}
		}
	}
	return "dev"
}()
