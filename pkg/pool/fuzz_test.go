// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"context"
	"io/fs"
	"sync"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

func FuzzBufferPoolConcurrent(f *testing.F) {
	f.Add(int64(0), 4)
	f.Add(int64(4096), 8)
	f.Add(int64(65536), 2)
	f.Add(int64(131072), 16)
	f.Add(int64(1), 1)

	f.Fuzz(func(t *testing.T, size int64, goroutines int) {
		if size < 0 || size > 1024*1024 || goroutines < 1 || goroutines > 32 {
			return
		}

		bp := NewBufferPool(goroutines)
		var wg sync.WaitGroup
		wg.Add(goroutines)

		for range goroutines {
			wg.Go(func() {
				defer wg.Done()
				buf := bp.Get(size)
				if int64(len(buf)) < size {
					t.Errorf("buffer too small: got %d, want >= %d", len(buf), size)
				}
				bp.Put(buf)
			})
		}
		wg.Wait()
	})
}

// compiledRules caches compiled YARA rules for scanner pool fuzzing.
var (
	compiledRules *yarax.Rules
	compiledOnce  sync.Once
)

func getCompiledRules(t *testing.T) *yarax.Rules {
	t.Helper()
	compiledOnce.Do(func() {
		fss := []fs.FS{rules.FS, thirdparty.FS}
		yrs, err := compile.Recursive(context.Background(), fss)
		if err != nil {
			return
		}
		compiledRules = yrs
	})
	return compiledRules
}

// FuzzScannerPoolConcurrent tests the ScannerPool under concurrent Get/Put
// with varying pool sizes and goroutine counts.
func FuzzScannerPoolConcurrent(f *testing.F) {
	f.Add(2, 4)
	f.Add(1, 1)
	f.Add(4, 8)
	f.Add(8, 2)
	f.Add(1, 16)

	f.Fuzz(func(t *testing.T, poolSize, goroutines int) {
		if poolSize < 1 || poolSize > 8 || goroutines < 1 || goroutines > 16 {
			return
		}

		yrs := getCompiledRules(t)
		if yrs == nil {
			t.Skip("failed to compile rules")
		}

		sp := NewScannerPool(yrs, poolSize)
		defer sp.Close()

		var wg sync.WaitGroup
		wg.Add(goroutines)

		for range goroutines {
			wg.Go(func() {
				defer wg.Done()
				scanner := sp.Get(yrs)
				if scanner == nil {
					t.Error("Get returned nil scanner")
					return
				}
				sp.Put(scanner)
			})
		}
		wg.Wait()
	})
}
