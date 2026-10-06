// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"path/filepath"
	"runtime"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

const scanTestMarkerRule = "scan_test_marker"

// scanTestMarkerRules compiles a rule set, separate from the bundled rules,
// that matches files containing "scan-test-marker".
func scanTestMarkerRules(t *testing.T) *yarax.Rules {
	t.Helper()
	yrs, err := yarax.Compile("rule " + scanTestMarkerRule + ": medium {\n  strings:\n    $a = \"scan-test-marker\"\n  condition:\n    $a\n}\n")
	if err != nil {
		t.Fatalf("compile marker rules: %v", err)
	}
	return yrs
}

func TestScanSinglePathUsesConfiguredRules(t *testing.T) {
	// Not parallel: switches the package-level scanner pool between rule sets.
	bundled, rfs := scanTestRules(t)
	marker := scanTestMarkerRules(t)
	path := scanTestWriteFile(t, filepath.Join(t.TempDir(), "marker.sh"), []byte("#!/bin/sh\necho scan-test-marker\n"))

	// Ending on the bundled rules leaves their pool active for later tests.
	tests := []struct {
		name     string
		rules    *yarax.Rules
		wantRule bool
	}{
		{name: "marker rules report the marker", rules: marker, wantRule: true},
		{name: "bundled rules after marker rules do not report the marker", rules: bundled},
		{name: "marker rules after bundled rules report the marker again", rules: marker, wantRule: true},
		{name: "bundled rules after a second switch do not report the marker", rules: bundled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := malcontent.Config{IncludeDataFiles: true, Rules: tt.rules, RuleFS: rfs}
			fr, err := scanSinglePath(t.Context(), c, path, rfs, path, "", nil)
			if err != nil {
				t.Fatalf("scanSinglePath: %v", err)
			}
			if got := hasRuleName(fr, scanTestMarkerRule); got != tt.wantRule {
				t.Errorf("%s reported: got = %t, want = %t", scanTestMarkerRule, got, tt.wantRule)
			}
		})
	}
}

func TestScannerPoolReplacement(t *testing.T) {
	// Not parallel: replaces the package-level scanner pool. GOMAXPROCS is
	// raised to at least two so that a pool build which changed it would show.
	bundled, _ := scanTestRules(t)
	marker := scanTestMarkerRules(t)
	procs := max(runtime.GOMAXPROCS(0), 2)
	prevProcs := runtime.GOMAXPROCS(procs)
	t.Cleanup(func() { runtime.GOMAXPROCS(prevProcs) })

	first := acquireScannerPool(bundled)
	// A caller that saw other rules active before taking the lock keeps the
	// pool built for its rules in the meantime.
	if got := replaceScannerPool(bundled); got != first || first.retired.Load() {
		t.Errorf("replacing a pool already built for the rules: got = %p (first retired %t), want = %p", got, first.retired.Load(), first)
	}
	if again := acquireScannerPool(bundled); again != first {
		t.Errorf("pool for unchanged rules: got = %p, want = %p", again, first)
	} else {
		again.release()
	}
	if allocs := testing.AllocsPerRun(100, func() { acquireScannerPool(bundled).release() }); allocs != 0 {
		t.Errorf("allocations borrowing the active pool: got = %v, want = 0", allocs)
	}

	replacement := acquireScannerPool(marker)
	if replacement == first || replacement.rules != marker {
		t.Fatalf("pool for new rules: got = %p (rules %p), want a new pool for rules %p", replacement, replacement.rules, marker)
	}
	if got := activeScannerPool.Load(); got != replacement {
		t.Errorf("active pool: got = %p, want = %p", got, replacement)
	}
	if got := runtime.GOMAXPROCS(0); got != procs {
		t.Errorf("GOMAXPROCS after building a pool: got = %d, want = %d", got, procs)
	}

	// A replaced pool keeps serving the scan that still borrows it.
	scanner := first.scanners.Get(bundled)
	if scanner == nil {
		t.Fatal("scanner from a replaced pool still in use: got = nil, want = open pool")
	}
	first.scanners.Put(scanner)

	// Its last release closes it, and a closed pool hands out no scanners.
	first.release()
	if got := first.scanners.Get(bundled); got != nil {
		t.Errorf("scanner from a replaced pool after its last release: got = %p, want = nil", got)
	}
	replacement.release()

	// Returning to the bundled rules closes the idle marker pool at once.
	restored := acquireScannerPool(bundled)
	restored.release()
	if restored == first || restored.rules != bundled {
		t.Errorf("pool after switching back: got = %p (rules %p), want a new pool for rules %p", restored, restored.rules, bundled)
	}
	if got := replacement.scanners.Get(marker); got != nil {
		t.Errorf("scanner from an idle replaced pool: got = %p, want = nil", got)
	}
}
