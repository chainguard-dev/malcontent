// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"io"
	"reflect"
	"testing"
)

// TestCallSiteCompatibility asserts that a Config built by struct literal is
// equivalent to one built via New + options for the same field values.
func TestCallSiteCompatibility(t *testing.T) {
	t.Parallel()

	tags := []string{"a", "b"}
	paths := []string{"/x", "/y"}

	literal := LibraryDefaults()
	literal.Concurrency = 7
	literal.IgnoreTags = tags
	literal.MaxDepth = 4
	literal.MinRisk = 2
	literal.ScanPaths = paths
	literal.Sensitivity = 3
	literal.Output = io.Discard

	folded := New(
		WithConcurrency(7),
		WithIgnoreTags(tags),
		WithMaxDepth(4),
		WithMinRisk(2),
		WithScanPaths(paths),
		WithSensitivity(3),
		WithOutput(io.Discard),
	)

	if !reflect.DeepEqual(literal, folded) {
		t.Fatalf("literal vs folded mismatch:\n literal=%+v\n folded =%+v", literal, folded)
	}
}

// TestLibraryDefaults_CoversCliFields confirms baseline CLI-populated fields
// receive non-zero or explicit defaults rather than panic-prone zero values.
func TestLibraryDefaults_CoversCliFields(t *testing.T) {
	t.Parallel()
	d := LibraryDefaults()
	if d.Concurrency <= 0 {
		t.Errorf("Concurrency: got %d, want >0", d.Concurrency)
	}
	if d.MaxDepth == 0 {
		t.Errorf("MaxDepth: got 0, want non-zero")
	}
	if d.Output == nil {
		t.Errorf("Output: got nil, want io.Discard")
	}
	if d.Sensitivity == 0 {
		t.Errorf("Sensitivity: got 0, want non-zero default")
	}
}
