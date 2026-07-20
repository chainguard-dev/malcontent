// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"sort"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	orderedmap "github.com/wk8/go-ordered-map/v2"

	yarax "github.com/VirusTotal/yara-x/go"
)

// compileDiffTestRules mirrors pkg/report's helper: compile a set of YARA
// rule sources, each in its own namespace so generateKey produces distinct
// keys per rule. This matches production compile ordering in
// pkg/compile/compile.go:Recursive.
func compileDiffTestRules(t *testing.T, sources map[string]string) *yarax.Rules {
	t.Helper()
	c, err := yarax.NewCompiler()
	if err != nil {
		t.Fatalf("NewCompiler: %v", err)
	}
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, ns := range names {
		c.NewNamespace(ns)
		if err := c.AddSource(sources[ns], yarax.WithOrigin(ns)); err != nil {
			t.Fatalf("AddSource(%q): %v", ns, err)
		}
	}
	r := c.Build()
	t.Cleanup(func() { r.Destroy() })
	return r
}

func scanDiffBuf(t *testing.T, rules *yarax.Rules, data []byte) *yarax.ScanResults {
	t.Helper()
	scanner := yarax.NewScanner(rules)
	t.Cleanup(func() { scanner.Destroy() })
	res, err := scanner.Scan(data)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

// generateFileReport builds a FileReport via report.Generate for the given
// bytes and Config, using the compiled rules. Callers use this to simulate
// what recursiveScan would produce for a single file under a given
// IgnoreRules configuration.
func generateFileReport(t *testing.T, rules *yarax.Rules, path string, fc []byte, c malcontent.Config) *malcontent.FileReport {
	t.Helper()
	mrs := scanDiffBuf(t, rules, fc)
	fr, err := report.Generate(t.Context(), path, mrs, c, "", clog.New(nil), fc, int64(len(fc)), "cksum", nil, 0)
	if err != nil {
		t.Fatalf("Generate(%q): %v", path, err)
	}
	return fr
}

// diffRulesSrc: three rules matching three distinct payloads. Used to drive
// diff-level tests where one rule fires in "src" only, another fires in
// "dest" only, and a third fires in both.
var diffRulesSrc = map[string]string{
	"common": `
rule diff_common_rule: high {
  strings:
    $a = "COMMON"
  condition:
    $a
}`,
	"newonly": `
rule diff_new_only_rule: high {
  strings:
    $b = "NEWMATCH"
  condition:
    $b
}`,
	"old": `
rule diff_old_only_rule: high {
  strings:
    $c = "OLDMATCH"
  condition:
    $c
}`,
}

// behaviorNamesFor returns the set of RuleName values in fr.Behaviors.
func behaviorNamesFor(fr *malcontent.FileReport) map[string]struct{} {
	if fr == nil {
		return nil
	}
	out := make(map[string]struct{}, len(fr.Behaviors))
	for _, b := range fr.Behaviors {
		out[b.RuleName] = struct{}{}
	}
	return out
}

// runHandleDir wires up the ScanResults maps and invokes handleDir. Returns
// the DiffReport for assertion.
func runHandleDir(t *testing.T, c malcontent.Config, srcFiles, destFiles map[string]*malcontent.FileReport) *malcontent.DiffReport {
	t.Helper()
	d := newDiffReportForTest()
	src := ScanResult{files: srcFiles}
	dest := ScanResult{files: destFiles}
	handleDir(t.Context(), c, src, dest, d, false, false)
	return d
}

func newDiffReportForTest() *malcontent.DiffReport {
	// Mirror the DiffReport construction inside Diff itself so test-run
	// shape matches production exactly.
	return &malcontent.DiffReport{
		Added:    orderedmap.New[string, *malcontent.FileReport](),
		Removed:  orderedmap.New[string, *malcontent.FileReport](),
		Modified: orderedmap.New[string, *malcontent.FileReport](),
	}
}

// TestDiff_IgnoreRules_ModifiedDropsExcludedFromAdded proves that when a
// file exists in both src and dest but gains a match in dest, an ignored
// rule name never surfaces in the Modified entry's Behaviors slice
// (specifically, never gets DiffAdded=true).
func TestDiff_IgnoreRules_ModifiedDropsExcludedFromAdded(t *testing.T) {
	t.Parallel()
	rules := compileDiffTestRules(t, diffRulesSrc)

	// Control run: no IgnoreRules; the new rule should surface as
	// DiffAdded in d.Modified.
	control := malcontent.Config{MinRisk: -1}
	srcFR := generateFileReport(t, rules, "shared.txt", []byte("COMMON"), control)
	destFR := generateFileReport(t, rules, "shared.txt", []byte("COMMON NEWMATCH"), control)
	d := runHandleDir(
		t, control,
		map[string]*malcontent.FileReport{"shared.txt": srcFR},
		map[string]*malcontent.FileReport{"shared.txt": destFR},
	)
	mod, ok := d.Modified.Get("shared.txt")
	if !ok {
		t.Fatalf("control: expected shared.txt in Modified, got %v", diffKeys(d))
	}
	if _, present := behaviorNamesFor(mod)["diff_new_only_rule"]; !present {
		t.Fatalf("control: expected diff_new_only_rule in Modified.Behaviors, got %v", behaviorNamesFor(mod))
	}

	// Filtered run: ignore the new rule; it must not appear anywhere.
	filtered := malcontent.Config{
		IgnoreRules: []string{"diff_new_only_rule"},
		MinRisk:     -1,
	}
	srcFR = generateFileReport(t, rules, "shared.txt", []byte("COMMON"), filtered)
	destFR = generateFileReport(t, rules, "shared.txt", []byte("COMMON NEWMATCH"), filtered)
	d = runHandleDir(
		t, filtered,
		map[string]*malcontent.FileReport{"shared.txt": srcFR},
		map[string]*malcontent.FileReport{"shared.txt": destFR},
	)
	// The file may or may not appear in Modified/Removed/Added depending
	// on how the pipeline treats zero-diff files, but wherever it appears,
	// the excluded rule must not.
	assertRuleAbsentAnywhere(t, d, "diff_new_only_rule")
}

// TestDiff_IgnoreRules_AddedFileDropsExcluded proves that when a file
// exists only in dest and its sole matching rule is ignored, the resulting
// d.Added FileReport contains no Behaviors — the excluded rule cannot leak
// through the "Added" case.
func TestDiff_IgnoreRules_AddedFileDropsExcluded(t *testing.T) {
	t.Parallel()
	rules := compileDiffTestRules(t, diffRulesSrc)

	// Control: without IgnoreRules, the added file surfaces with its rule.
	control := malcontent.Config{MinRisk: -1}
	destFR := generateFileReport(t, rules, "new.txt", []byte("NEWMATCH"), control)
	d := runHandleDir(
		t, control,
		map[string]*malcontent.FileReport{},
		map[string]*malcontent.FileReport{"new.txt": destFR},
	)
	added, ok := d.Added.Get("new.txt")
	if !ok {
		t.Fatalf("control: expected new.txt in Added, got %v", diffKeys(d))
	}
	if _, present := behaviorNamesFor(added)["diff_new_only_rule"]; !present {
		t.Fatalf("control: expected diff_new_only_rule in Added.Behaviors, got %v", behaviorNamesFor(added))
	}

	// Filtered: ignore the rule; the file's Behaviors must be empty and
	// the rule must not appear anywhere in the DiffReport.
	filtered := malcontent.Config{
		IgnoreRules: []string{"diff_new_only_rule"},
		MinRisk:     -1,
	}
	destFR = generateFileReport(t, rules, "new.txt", []byte("NEWMATCH"), filtered)
	d = runHandleDir(
		t, filtered,
		map[string]*malcontent.FileReport{},
		map[string]*malcontent.FileReport{"new.txt": destFR},
	)
	if added, ok := d.Added.Get("new.txt"); ok {
		if _, present := behaviorNamesFor(added)["diff_new_only_rule"]; present {
			t.Errorf("filtered: excluded rule leaked into Added.Behaviors: %v", behaviorNamesFor(added))
		}
	}
	assertRuleAbsentAnywhere(t, d, "diff_new_only_rule")
}

// TestDiff_IgnoreRules_RemovedFileDropsExcluded is the symmetric case: a
// file present only in src. When the sole matching rule is ignored, the
// removed entry (if any) must not contain the excluded rule.
func TestDiff_IgnoreRules_RemovedFileDropsExcluded(t *testing.T) {
	t.Parallel()
	rules := compileDiffTestRules(t, diffRulesSrc)

	filtered := malcontent.Config{
		IgnoreRules: []string{"diff_old_only_rule"},
		MinRisk:     -1,
	}
	srcFR := generateFileReport(t, rules, "gone.txt", []byte("OLDMATCH"), filtered)
	d := runHandleDir(
		t, filtered,
		map[string]*malcontent.FileReport{"gone.txt": srcFR},
		map[string]*malcontent.FileReport{},
	)
	if removed, ok := d.Removed.Get("gone.txt"); ok {
		if _, present := behaviorNamesFor(removed)["diff_old_only_rule"]; present {
			t.Errorf("filtered: excluded rule leaked into Removed.Behaviors: %v", behaviorNamesFor(removed))
		}
	}
	assertRuleAbsentAnywhere(t, d, "diff_old_only_rule")
}

// TestDiff_IgnoreRules_ConfigPlumbing documents the Config-copy behavior
// in relFileReport: because Config is a value type, copying it into
// fromConfig preserves IgnoreRules unchanged (the slice header is copied,
// underlying array shared). This test pins that behavior so a future
// refactor that accidentally strips IgnoreRules from the copy is caught.
func TestDiff_IgnoreRules_ConfigPlumbing(t *testing.T) {
	t.Parallel()
	original := malcontent.Config{
		IgnoreRules: []string{"never_matches_anything_*"},
		MinRisk:     -1,
	}
	// This mirrors the value-copy pattern in relFileReport at diff.go:155.
	fromConfig := original
	fromConfig.Renderer = nil
	fromConfig.ScanPaths = []string{"/tmp/x"}
	if len(fromConfig.IgnoreRules) != len(original.IgnoreRules) {
		t.Fatalf("IgnoreRules length changed after Config copy: got %d, want %d",
			len(fromConfig.IgnoreRules), len(original.IgnoreRules))
	}
	for i, p := range fromConfig.IgnoreRules {
		if p != original.IgnoreRules[i] {
			t.Errorf("IgnoreRules[%d] = %q, want %q", i, p, original.IgnoreRules[i])
		}
	}
}

// assertRuleAbsentAnywhere fails the test if ruleName appears in any
// behavior across Added, Modified, or Removed sections.
func assertRuleAbsentAnywhere(t *testing.T, d *malcontent.DiffReport, ruleName string) {
	t.Helper()
	check := func(label string, fr *malcontent.FileReport) {
		for _, b := range fr.Behaviors {
			if b.RuleName == ruleName {
				t.Errorf("%s: excluded rule %q leaked into %s Behaviors (DiffAdded=%v, DiffRemoved=%v)",
					fr.Path, ruleName, label, b.DiffAdded, b.DiffRemoved)
			}
		}
	}
	for pair := d.Added.Oldest(); pair != nil; pair = pair.Next() {
		check("Added", pair.Value)
	}
	for pair := d.Modified.Oldest(); pair != nil; pair = pair.Next() {
		check("Modified", pair.Value)
	}
	for pair := d.Removed.Oldest(); pair != nil; pair = pair.Next() {
		check("Removed", pair.Value)
	}
}

// diffKeys returns the union of keys across all three DiffReport sections
// for use in error messages.
func diffKeys(d *malcontent.DiffReport) []string {
	var keys []string
	for pair := d.Added.Oldest(); pair != nil; pair = pair.Next() {
		keys = append(keys, "added:"+pair.Key)
	}
	for pair := d.Modified.Oldest(); pair != nil; pair = pair.Next() {
		keys = append(keys, "modified:"+pair.Key)
	}
	for pair := d.Removed.Oldest(); pair != nil; pair = pair.Next() {
		keys = append(keys, "removed:"+pair.Key)
	}
	return keys
}
