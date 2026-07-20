// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidateIgnoreRules checks that every non-empty pattern in patterns is a
// syntactically valid filepath.Match glob. It returns an error wrapping
// filepath.ErrBadPattern for the first malformed entry so the CLI can fail
// fast at startup rather than silently no-matching at scan time.
//
// An empty or nil slice returns nil (the exclusion filter is a no-op).
// Whitespace-only entries are ignored, mirroring how the CLI splits
// comma-separated flag values that may contain accidental blank tokens.
func ValidateIgnoreRules(patterns []string) error {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := filepath.Match(p, ""); err != nil {
			return fmt.Errorf("invalid --ignore-rules pattern %q: %w", p, err)
		}
	}
	return nil
}

// ruleExcluded reports whether the YARA rule identified by name should be
// filtered out of the report. patterns are filepath.Match glob patterns
// (an identifier with no metacharacters matches itself). First-match-wins
// over the pattern list.
//
// A per-pattern parse error is treated as a non-match — the pattern is
// skipped and iteration continues. Callers are expected to have run
// ValidateIgnoreRules at startup so this path is not reached in practice;
// the defensive behavior is here so a stray malformed pattern cannot
// silently swallow every match ("match-all on error").
func ruleExcluded(name string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ok, err := filepath.Match(p, name)
		if err != nil {
			continue
		}
		if ok {
			return true
		}
	}
	return false
}
