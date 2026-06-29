// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

var thirdPartyRuleDecl = regexp.MustCompile(`(?m)^\s*(?:private\s+)?rule\s+(\w+)`)

// embeddedThirdPartyRules returns the set of YARA rule identifiers defined
// across the vendored third-party rule sets.
func embeddedThirdPartyRules(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	err := fs.WalkDir(thirdparty.FS, "yara", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch {
		case strings.HasSuffix(path, ".yar"), strings.HasSuffix(path, ".yara"):
		default:
			return nil
		}
		b, err := fs.ReadFile(thirdparty.FS, path)
		if err != nil {
			return err
		}
		for _, m := range thirdPartyRuleDecl.FindAllStringSubmatch(string(b), -1) {
			names[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk third-party rules: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("no embedded third-party rules found; is third_party/yara populated?")
	}
	return names
}

// TestIsSeverityDriven guards the allowlist that scopes severity-metadata
// risk to opted-in sources: GuardDog rules are severity-driven, while other
// vendored sources (which also carry severity meta) must keep behaviorRisk's
// namespace-reputation scoring.
func TestIsSeverityDriven(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ns   string
		want bool
	}{
		{"yara/guarddog/threat-runtime-keylogging.yar", true},
		{"yara/YARAForge/yara-rules-full.yar", false},
		{"yara/elastic/Linux_Trojan_Rotajakiro.yar", false},
		{"yara/JPCERT/foo.yar", false},
		{"fs/file/delete.yara", false},
	}
	for _, tt := range tests {
		if got := isSeverityDriven(tt.ns); got != tt.want {
			t.Errorf("isSeverityDriven(%q) = %v, want %v", tt.ns, got, tt.want)
		}
	}
}

// TestThirdPartyRiskOverrides guards the hand-maintained risk-override table:
// every value must be a valid risk score and every key must still name a
// vendored rule (catching upstream renames or removals).
func TestThirdPartyRiskOverrides(t *testing.T) {
	t.Parallel()
	rules := embeddedThirdPartyRules(t)
	for name, score := range thirdPartyRiskOverrides {
		if _, ok := RiskLevels[score]; !ok {
			t.Errorf("thirdPartyRiskOverrides[%q] = %d is not a valid risk score", name, score)
		}
		if !rules[name] {
			t.Errorf("thirdPartyRiskOverrides references %q, which is not a vendored third-party rule (renamed or removed upstream?)", name)
		}
	}
}
