// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"io/fs"
	"slices"
	"testing"
	"testing/fstest"

	yarax "github.com/VirusTotal/yara-x/go"
)

// TestRecursiveLeavesEcosystemEmpty compiles rules that, as GuardDog's do,
// compare the ecosystem global against a package ecosystem. Malcontent scans
// files rather than packages, so only the rule expecting no ecosystem
// matches.
func TestRecursiveLeavesEcosystemEmpty(t *testing.T) {
	t.Parallel()
	src := `
rule pypi_only { strings: $pth = ".pth" condition: ecosystem == "pypi" and $pth }
rule no_ecosystem { strings: $pth = ".pth" condition: ecosystem == "" and $pth }
`
	rules, err := Recursive(t.Context(), []fs.FS{fstest.MapFS{"guarddog/autostart.yar": {Data: []byte(src)}}})
	if err != nil {
		t.Fatalf("Recursive: %v", err)
	}
	defer rules.Destroy()
	s := yarax.NewScanner(rules)
	defer s.Destroy()
	results, err := s.Scan([]byte("open(site.getsitepackages()[0] + '/evil.pth', 'w')"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	matched := results.MatchingRules()
	got := make([]string, 0, len(matched))
	for _, r := range matched {
		got = append(got, r.Identifier())
	}
	if want := []string{"no_ecosystem"}; !slices.Equal(got, want) {
		t.Errorf("matching rules: got = %q, want = %q", got, want)
	}
}
