// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/chainguard-dev/malcontent/internal/yrx"
)

// duplicateRuleFiles returns, for each content shared by more than one rule
// file in fsys, the files that hold it. Files holding only white space
// declare no rules, so their copies cost nothing and are left out.
func duplicateRuleFiles(t *testing.T, fsys fs.FS) map[string][]string {
	t.Helper()
	byDigest := map[string][]string{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isRuleFile(path) {
			return err
		}
		bs, err := fs.ReadFile(fsys, path)
		if err != nil || len(bytes.TrimSpace(bs)) == 0 {
			return err
		}
		sum := sha256.Sum256(bs)
		key := hex.EncodeToString(sum[:])
		byDigest[key] = append(byDigest[key], path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk rules: %v", err)
	}
	maps.DeleteFunc(byDigest, func(_ string, files []string) bool { return len(files) < 2 })
	return byDigest
}

// TestRuleFilesUnique fails when a rule file is vendored twice, which
// compiles and scans its rules twice and lets a stale copy outlive updates.
func TestRuleFilesUnique(t *testing.T) {
	t.Parallel()
	same := []byte("rule same { condition: true }")
	tests := []struct {
		name string
		fsys fs.FS
		want int
	}{
		{"a file copied into a subdirectory is reported", fstest.MapFS{"feed/a.yara": {Data: same}, "feed/old/a.yara": {Data: same}}, 1},
		{"files with distinct content are fine", fstest.MapFS{"feed/a.yara": {Data: same}, "feed/b.yara": {Data: []byte("rule b { condition: true }")}}, 0},
		{"empty files are not copies", fstest.MapFS{"feed/a.yara": {Data: []byte("\n")}, "feed/b.yara": {Data: []byte("\n")}}, 0},
		{"the bundled first-party rules hold no copies", FS, 0},
		{"the bundled third-party rules hold no copies", getAllRuleFS()[1], 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := duplicateRuleFiles(t, tt.fsys); len(got) != tt.want {
				t.Errorf("duplicated rule files: got = %v, want %d groups", got, tt.want)
			}
		})
	}
}

// TestFirstPartyRuleIdentifiersUnique fails when a first-party rule shares
// its name with another bundled rule. Override rules and --ignore-rules name
// rules by identifier, so a shared name reaches every rule that carries it.
// Third-party feeds that repeat a rule across their own files are left as
// upstream ships them.
func TestFirstPartyRuleIdentifiersUnique(t *testing.T) {
	t.Parallel()
	yrs, _, err := compileRecursive(t.Context(), getAllRuleFS())
	if err != nil {
		t.Fatalf("compileRecursive: %v", err)
	}
	t.Cleanup(func() { yrx.Destroy(yrs) })
	namespaces := map[string][]string{}
	for _, r := range yrs.Slice() {
		namespaces[r.Identifier()] = append(namespaces[r.Identifier()], r.Namespace())
	}
	for _, id := range slices.Sorted(maps.Keys(namespaces)) {
		ns := namespaces[id]
		firstParty := slices.ContainsFunc(ns, func(n string) bool { return !strings.HasPrefix(n, "yara/") })
		if len(ns) > 1 && firstParty {
			t.Errorf("rule %s is declared in %q", id, ns)
		}
	}
}
