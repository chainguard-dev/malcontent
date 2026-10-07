// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"io/fs"
	"regexp"
	"testing"

	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// wholeFileSHA256 matches a rule hashing the whole file with the hash module.
var wholeFileSHA256 = regexp.MustCompile(`\bhash\.sha256\s*\(\s*0\s*,\s*filesize\s*\)`)

// TestRulesCompareFileSHA256 checks that no bundled rule hashes the whole
// file with the hash module, which rereads every file scanned; rules compare
// the FileSHA256 global instead, and third_party/yara/update.sh rewrites
// third-party rules to do so.
func TestRulesCompareFileSHA256(t *testing.T) {
	t.Parallel()
	for name, fsys := range map[string]fs.FS{"rules": rules.FS, "third_party": thirdparty.FS} {
		checked := 0
		err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !isRuleFile(path) {
				return err
			}
			src, err := fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}
			checked++
			if loc := wholeFileSHA256.FindIndex(src); loc != nil {
				t.Errorf("%s/%s: got %q, want file_sha256", name, path, src[loc[0]:loc[1]])
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", name, err)
		}
		if checked == 0 {
			t.Errorf("%s: got no rule files, want the bundled rules", name)
		}
	}
}
