// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package release

import "sync/atomic"

// BuildCommit is populated at link time via
// `-ldflags "-X github.com/chainguard-dev/malcontent/pkg/release.BuildCommit=<sha>"`.
// When unset, ResolveRuleURLCommit returns "" (callers fall back to "main").
var BuildCommit string

// ruleURLRefOverride, when set, takes priority over BuildCommit in
// ResolveRuleURLCommit. This keeps regenerated sample testdata stable
// (always blob/main) regardless of how the binary was built.
var ruleURLRefOverride atomic.Pointer[string]

// PinRuleURLRef forces ResolveRuleURLCommit to return ref instead of
// deriving the value from BuildCommit. The pin is concurrency-safe:
// callers set it before scan goroutines start, but the atomic guarantees
// correctness under -race.
func PinRuleURLRef(ref string) {
	ruleURLRefOverride.Store(&ref)
}

// ResetRuleURLRef clears any override set by PinRuleURLRef, restoring
// the default BuildCommit-based behavior. Exported for test cleanup.
func ResetRuleURLRef() {
	ruleURLRefOverride.Store(nil)
}

// ResolveRuleURLCommit returns the commit ref used in generated rule
// deep-link URLs. When an explicit pin has been set via PinRuleURLRef
// that value wins unconditionally. Otherwise a canonical 40-char
// lowercase hex BuildCommit, injected at link time by production builds,
// yields that pinned commit. Any other BuildCommit value yields "";
// callers should fall back to "main" to produce a working URL rather
// than suppressing it.
func ResolveRuleURLCommit() string {
	if p := ruleURLRefOverride.Load(); p != nil {
		return *p
	}
	if isFortyHexLower(BuildCommit) {
		return BuildCommit
	}
	return ""
}

// isFortyHexLower reports whether s is exactly 40 chars of [0-9a-f].
// Upper-case hex is rejected to keep the URL canonical and to prevent
// case-only spoofing.
func isFortyHexLower(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
