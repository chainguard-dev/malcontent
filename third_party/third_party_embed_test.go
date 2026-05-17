// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package thirdparty

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func isYaraRule(name string) bool {
	return strings.HasSuffix(name, ".yar") || strings.HasSuffix(name, ".yara")
}

func TestEmbedCoversAllYaraRulesOnDisk(t *testing.T) {
	t.Parallel()

	const root = "yara"
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("on-disk %q not present (source tree unavailable); skipping", root)
		}
		t.Fatalf("stat %q: %v", root, err)
	}

	disk := map[string]struct{}{}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if isYaraRule(d.Name()) {
			disk[filepath.ToSlash(path)] = struct{}{}
		}
		return nil
	}); err != nil {
		t.Fatalf("walk on-disk %q: %v", root, err)
	}

	embedded := map[string]struct{}{}
	if err := fs.WalkDir(FS, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if isYaraRule(d.Name()) {
			embedded[path] = struct{}{}
		}
		return nil
	}); err != nil {
		t.Fatalf("walk embed.FS %q: %v", root, err)
	}

	var missingFromEmbed []string
	for p := range disk {
		if _, ok := embedded[p]; !ok {
			missingFromEmbed = append(missingFromEmbed, p)
		}
	}
	var missingFromDisk []string
	for p := range embedded {
		if _, ok := disk[p]; !ok {
			missingFromDisk = append(missingFromDisk, p)
		}
	}
	sort.Strings(missingFromEmbed)
	sort.Strings(missingFromDisk)

	for _, p := range missingFromEmbed {
		t.Errorf("file %q exists on disk but is not embedded -- embed pattern is missing it.", p)
	}
	for _, p := range missingFromDisk {
		t.Errorf("file %q is embedded but does not exist on disk -- embed pattern is missing it.", p)
	}

	if len(disk) == 0 {
		t.Fatalf("on-disk walk produced zero YARA rule files; test is not meaningful")
	}
}
