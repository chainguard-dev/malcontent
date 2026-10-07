// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// BenchmarkWalkScanPath walks a scan path of 8,192 files in 1,024
// directories four levels deep.
func BenchmarkWalkScanPath(b *testing.B) {
	dir := b.TempDir()
	for i := range 8192 {
		name := filepath.Join("a", fmt.Sprintf("b%d", i%32), fmt.Sprintf("c%d", i%1024), fmt.Sprintf("f%d", i))
		if err := file.MkdirAllIn(dir, filepath.Dir(name), 0o700); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		if err := file.WriteFileIn(dir, name, []byte("x"), 0o600); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		w, files, err := walkScanPath(b.Context(), dir)
		if err != nil || len(files) != 8192 {
			b.Fatalf("walkScanPath: got = (%d files, %v), want = (8192, nil)", len(files), err)
		}
		w.close()
	}
}
