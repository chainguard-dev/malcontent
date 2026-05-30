// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"fmt"
	"runtime/debug"
)

// BuildCommit is populated at link time via
// `-ldflags "-X github.com/chainguard-dev/malcontent/pkg/release.BuildCommit=<sha>"`.
// When unset, the resolvers fall back to the VCS revision recorded in the
// embedded build info, then to the literal "main".
var BuildCommit string

// ResolveCommitStrict returns the resolved commit SHA only when it is a
// valid 40-character lowercase hex value. The "main" fallback is treated
// as an error so callers that embed the value in persistent artifacts
// (fixture URLs, release manifests) cannot silently ship a placeholder.
func ResolveCommitStrict() (string, error) {
	return resolveCommitStrictFrom(readVCSRevision(), BuildCommit)
}

// ResolveRuleURLCommit returns the commit ref used in generated rule
// deep-link URLs. A canonical 40-char lowercase hex BuildCommit, injected
// at link time by production builds, yields that pinned commit. Any other
// BuildCommit value yields "" so the rule URL is suppressed entirely.
func ResolveRuleURLCommit() string {
	if isFortyHexLower(BuildCommit) {
		return BuildCommit
	}
	return ""
}

// resolveCommitStrictFrom is the seam used by ResolveCommitStrict tests.
func resolveCommitStrictFrom(vcsRev, buildCommit string) (string, error) {
	resolved := pickCommit(vcsRev, buildCommit)
	if !isFortyHexLower(resolved) {
		return "", fmt.Errorf("release commit unresolved: %q is not a 40-character lowercase hex SHA", resolved)
	}
	return resolved, nil
}

// readVCSRevision returns the `vcs.revision` build-info setting if
// present, otherwise the empty string. It never panics.
func readVCSRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}

// pickCommit applies the priority chain: VCS revision, then BuildCommit,
// then "main". Each candidate must satisfy isFortyHexLower to be accepted;
// any other value is treated as absent.
func pickCommit(vcsRev, buildCommit string) string {
	if isFortyHexLower(vcsRev) {
		return vcsRev
	}
	if isFortyHexLower(buildCommit) {
		return buildCommit
	}
	return "main"
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
