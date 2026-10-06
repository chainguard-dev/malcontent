// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"io/fs"
	"runtime"
	"slices"
	"sync"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// FuzzBufferPoolConcurrent checks that concurrent holders never share a
// buffer: each fills the buffer it holds with its own mark, yields, and
// verifies that no other holder wrote to it before returning it.
func FuzzBufferPoolConcurrent(f *testing.F) {
	f.Add(4, 8)
	f.Add(1, 1)
	f.Add(16, 2)
	f.Add(32, 16)

	f.Fuzz(func(t *testing.T, goroutines, rounds int) {
		if goroutines < 1 || goroutines > 32 || rounds < 1 || rounds > 64 {
			return
		}

		var bp BufferPool
		var wg sync.WaitGroup
		for id := range goroutines {
			mark := byte(id)
			wg.Go(func() {
				for range rounds {
					buf := bp.Get()
					if len(buf) != int(file.ExtractBuffer) {
						t.Errorf("buffer length: got = %d, want = %d", len(buf), file.ExtractBuffer)
						return
					}
					for i := range buf {
						buf[i] = mark
					}
					runtime.Gosched()
					if i := slices.IndexFunc(buf, func(b byte) bool { return b != mark }); i >= 0 {
						t.Errorf("byte %d of a held buffer: got = %d, want = %d", i, buf[i], mark)
						return
					}
					bp.Put(buf)
				}
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
		yrs, err := compile.Recursive(t.Context(), fss)
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
		for range goroutines {
			wg.Go(func() {
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
