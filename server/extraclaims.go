// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"fmt"
	"log/slog"
)

// withExtraClaims merges flattened extra claims from a list of capRule into the provided map[string]any,
// returning a map[string]any that combines both sources.
//
// These extra claims are flattened and merged into the base map unless they conflict with protected claims.
// Claims defined in openIDSupportedClaims are considered protected and cannot be overwritten.
// If an extra claim attempts to overwrite a protected claim, an error is returned.
//
// Returns the merged claims map or an error if any protected claim is violated or JSON (un)marshaling fails.
func withExtraClaims(claimMap map[string]any, rules []capRule) (map[string]any, error) {
	// Convert views.Slice to a map[string]struct{} for efficient lookup
	protected := make(map[string]struct{}, len(openIDSupportedClaims.AsSlice()))
	for _, claim := range openIDSupportedClaims.AsSlice() {
		protected[claim] = struct{}{}
	}

	// Merge extra claims
	extra := flattenExtraClaims(rules)
	for k, v := range extra {
		if _, isProtected := protected[k]; isProtected {
			slog.Info("Skip overwriting of existing claim", slog.String("claim", k))
			return nil, fmt.Errorf("extra claim %q overwriting existing claim", k)
		}

		claimMap[k] = v
	}

	return claimMap, nil
}

// flattenExtraClaims merges all ExtraClaims from a slice of capRule into a single map.
// It deduplicates values for each claim and preserves the original input type:
// scalar values remain scalars, and slices are returned as deduplicated []any slices.
func flattenExtraClaims(rules []capRule) map[string]any {
	// sets stores deduplicated stringified values for each claim key.
	sets := make(map[string]map[string]struct{})

	// isSlice tracks whether each claim was originally provided as a slice.
	isSlice := make(map[string]bool)

	for _, rule := range rules {
		for claim, raw := range rule.ExtraClaims {
			// Track whether the claim was provided as a slice
			switch raw.(type) {
			case []string, []any:
				isSlice[claim] = true
			default:
				// Only mark as scalar if this is the first time we've seen this claim
				if _, seen := isSlice[claim]; !seen {
					isSlice[claim] = false
				}
			}

			// Add the claim value(s) into the deduplication set
			addClaimValue(sets, claim, raw)
		}
	}

	// Build final result: either scalar or slice depending on original type
	result := make(map[string]any)
	for claim, valSet := range sets {
		if isSlice[claim] {
			// Claim was provided as a slice: output as []any
			var vals []any
			for val := range valSet {
				vals = append(vals, val)
			}
			result[claim] = vals
		} else {
			// Claim was a scalar: return a single value
			for val := range valSet {
				result[claim] = val
				break // only one value is expected
			}
		}
	}

	return result
}
