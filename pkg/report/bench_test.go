// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"strings"
	"testing"
)

// BenchmarkContainsFoldASCII exercises the allocation-free ASCII fold search.
func BenchmarkContainsFoldASCII(b *testing.B) {
	haystack := "anti-static/YARAForge/CRITICAL/generic_malware_family"
	needle := "generic"
	b.ReportAllocs()
	for b.Loop() {
		_ = containsFoldASCII(haystack, needle)
	}
}

// BenchmarkNsSecondSegment measures the namespace-segment slice.
func BenchmarkNsSecondSegment(b *testing.B) {
	ns := "thirdparty/YARAForge/CRITICAL/rule_namespace"
	b.ReportAllocs()
	for b.Loop() {
		_ = nsSecondSegment(ns)
	}
}

// BenchmarkMatchToString measures the per-match string rewrite.
func BenchmarkMatchToString(b *testing.B) {
	rule := "anti-static/base64/eval"
	m := strings.Repeat("payload", 16)
	b.ReportAllocs()
	for b.Loop() {
		_ = matchToString(rule, m)
	}
}

// BenchmarkTrimPrefixes exercises the prefix-strip helper at common cardinality.
func BenchmarkTrimPrefixes(b *testing.B) {
	path := "/private/var/folders/aa/bb/T/scan-abc/bin/payload"
	prefixes := []string{"/private/var/folders/aa/bb/T/scan-abc", "/tmp", "/var/tmp"}
	b.ReportAllocs()
	for b.Loop() {
		_ = TrimPrefixes(path, prefixes)
	}
}
