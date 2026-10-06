// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"runtime"
	"sync"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/malcontent/pkg/file"
)

// poolReturns reports whether bp hands back the buffer starting at &want[0]
// from Get after buf is Put. sync.Pool may discard any single Put (the race
// detector does so at random), so a retained buffer is detected by retrying,
// while a dropped buffer never comes back and Get allocates a distinct one.
func poolReturns(bp *BufferPool, buf, want []byte) bool {
	for range 64 {
		bp.Put(buf)
		if got := bp.Get(); &got[0] == &want[0] {
			return true
		}
	}
	return false
}

func TestBufferPoolGetLength(t *testing.T) {
	t.Parallel()
	want := int(file.ExtractBuffer)

	var bp BufferPool
	first := bp.Get()
	if len(first) != want || cap(first) != want {
		t.Errorf("new buffer: got len = %d, cap = %d, want = %d", len(first), cap(first), want)
	}
	if !poolReturns(&bp, first[:1], first) {
		t.Fatal("pooled buffer: got = never reused, want = reused")
	}
	again := bp.Get()
	if len(again) != want || cap(again) != want {
		t.Errorf("reused buffer: got len = %d, cap = %d, want = %d", len(again), cap(again), want)
	}
}

func TestBufferPoolPutRetention(t *testing.T) {
	t.Parallel()
	size := int(file.ExtractBuffer)

	tests := []struct {
		name string
		// buf returns the slice to Put, given a buffer from Get.
		buf        func(got []byte) []byte
		wantReused bool
	}{
		{name: "buffer from Get is reused", buf: func(got []byte) []byte { return got }, wantReused: true},
		{name: "buffer resliced from its start is reused", buf: func(got []byte) []byte { return got[:10] }, wantReused: true},
		{name: "empty reslice from its start is reused", buf: func(got []byte) []byte { return got[:0] }, wantReused: true},
		{name: "buffer resliced past its start is dropped", buf: func(got []byte) []byte { return got[1:] }},
		{name: "smaller foreign buffer is dropped", buf: func([]byte) []byte { return make([]byte, size-1) }},
		{name: "larger foreign buffer is dropped", buf: func([]byte) []byte { return make([]byte, size+1) }},
		{name: "larger capacity behind a full-length slice is dropped", buf: func([]byte) []byte { return make([]byte, size, size+1) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var bp BufferPool
			buf := tt.buf(bp.Get())
			want := buf[:cap(buf)]
			if got := poolReturns(&bp, buf, want); got != tt.wantReused {
				t.Errorf("buffer reused: got = %v, want = %v", got, tt.wantReused)
			}
		})
	}
}

func TestBufferPoolPutIgnoresNil(t *testing.T) {
	t.Parallel()
	var bp BufferPool
	bp.Put(nil)
	if got := len(bp.Get()); got != int(file.ExtractBuffer) {
		t.Errorf("buffer after Put(nil): got len = %d, want = %d", got, file.ExtractBuffer)
	}
}

// TestBufferPoolKeepsContents pins that the pool never clears a buffer.
// Callers overwrite a buffer before reading it, so clearing would only cost
// time.
func TestBufferPoolKeepsContents(t *testing.T) {
	t.Parallel()
	var bp BufferPool
	buf := bp.Get()
	for i := range buf {
		buf[i] = byte(i%251 + 1)
	}
	if !poolReturns(&bp, buf, buf) {
		t.Fatal("pooled buffer: got = never reused, want = reused")
	}
	for i, b := range buf {
		if want := byte(i%251 + 1); b != want {
			t.Fatalf("byte %d after reuse: got = %d, want = %d", i, b, want)
		}
	}
}

func TestNewScannerPool(t *testing.T) {
	t.Parallel()
	// Create a minimal YARA rule for testing
	compiler, err := yarax.NewCompiler()
	if err != nil {
		t.Fatalf("failed to create compiler: %v", err)
	}

	err = compiler.AddSource(`
		rule test_rule {
			strings:
				$a = "test"
			condition:
				$a
		}
	`)
	if err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	rules := compiler.Build()
	t.Cleanup(func() { rules.Destroy() })

	procs := runtime.GOMAXPROCS(0)
	tests := []struct {
		name  string
		count int
		want  int
	}{
		{"negative count holds one scanner", -1, 1},
		{"zero count holds one scanner", 0, 1},
		{"single scanner", 1, 1},
		{"count at GOMAXPROCS is kept", procs, procs},
		{"count above GOMAXPROCS is capped", procs + 1, procs},
		{"unreasonable count is capped", 65535, procs},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sp := NewScannerPool(rules, tt.count)
			if sp == nil {
				t.Fatal("NewScannerPool returned nil")
			}
			defer sp.Close()

			if got := len(sp.scanners); got != tt.want {
				t.Errorf("pool size: got = %d, want = %d", got, tt.want)
			}

			scanner := sp.Get(rules)
			if scanner == nil {
				t.Error("Get returned nil scanner")
			}
			sp.Put(scanner)
		})
	}
}

func TestScannerPoolGet(t *testing.T) {
	t.Parallel()
	compiler, err := yarax.NewCompiler()
	if err != nil {
		t.Fatalf("failed to create compiler: %v", err)
	}

	err = compiler.AddSource(`
		rule test_rule {
			strings:
				$a = "test"
			condition:
				$a
		}
	`)
	if err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	rules := compiler.Build()
	t.Cleanup(func() { rules.Destroy() })

	t.Run("get from pool", func(t *testing.T) {
		t.Parallel()
		sp := NewScannerPool(rules, 2)
		defer sp.Close()

		scanner := sp.Get(rules)
		if scanner == nil {
			t.Fatal("Get returned nil")
		}

		sp.Put(scanner)
	})

	t.Run("get from nil pool", func(t *testing.T) {
		t.Parallel()
		var sp *ScannerPool
		scanner := sp.Get(rules)
		if scanner == nil {
			t.Error("Get on nil pool should return new scanner, got nil")
		} else {
			scanner.Destroy()
		}
	})
}

func TestScannerPoolPut(t *testing.T) {
	t.Parallel()
	compiler, err := yarax.NewCompiler()
	if err != nil {
		t.Fatalf("failed to create compiler: %v", err)
	}

	err = compiler.AddSource(`
		rule test_rule {
			strings:
				$a = "test"
			condition:
				$a
		}
	`)
	if err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	rules := compiler.Build()
	t.Cleanup(func() { rules.Destroy() })

	sp := NewScannerPool(rules, 2)
	t.Cleanup(func() { sp.Close() })

	t.Run("put nil scanner", func(t *testing.T) {
		t.Parallel()
		sp.Put(nil)
	})

	t.Run("put valid scanner", func(t *testing.T) {
		t.Parallel()
		s1 := sp.Get(rules)
		sp.Put(s1)

		s2 := sp.Get(rules)
		if s2 == nil {
			t.Error("failed to get scanner back from pool")
		}
		sp.Put(s2)
	})

	t.Run("fill pool", func(t *testing.T) {
		t.Parallel()
		s1 := sp.Get(rules)
		s2 := sp.Get(rules)

		sp.Put(s1)
		sp.Put(s2)

		// add a third scanner to the already full pool (should be a NOP)
		s3 := yarax.NewScanner(rules)
		sp.Put(s3)
		s3.Destroy()
	})
}

func TestScannerPoolCloseDestroysScanners(t *testing.T) {
	t.Parallel()
	rules, err := yarax.Compile("rule pool_close { condition: true }")
	if err != nil {
		t.Fatalf("compile test rule: %v", err)
	}
	t.Cleanup(rules.Destroy)

	sp := NewScannerPool(rules, 2)
	held := make([]*yarax.Scanner, 0, cap(sp.scanners))
	for range cap(sp.scanners) {
		held = append(held, sp.Get(rules))
	}
	for i, scanner := range held {
		if _, err := scanner.Scan([]byte("data")); err != nil {
			t.Fatalf("scan with scanner %d before Close: got err = %v, want = nil", i, err)
		}
		sp.Put(scanner)
	}

	sp.Close()
	sp.Close() // A second Close does nothing.

	// A destroyed scanner has no native scanner left, so scanning with it
	// fails instead of matching.
	for i, scanner := range held {
		if _, err := scanner.Scan([]byte("data")); err == nil {
			t.Errorf("scan with scanner %d after Close: got err = nil, want = error from a destroyed scanner", i)
		}
	}
}

func TestScannerPoolConcurrency(t *testing.T) {
	t.Parallel()
	compiler, err := yarax.NewCompiler()
	if err != nil {
		t.Fatalf("failed to create compiler: %v", err)
	}

	err = compiler.AddSource(`
		rule test_rule {
			strings:
				$a = "test"
			condition:
				$a
		}
	`)
	if err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	rules := compiler.Build()
	defer rules.Destroy()

	sp := NewScannerPool(rules, 3)
	defer sp.Close()

	var wg sync.WaitGroup
	iterations := 50

	for range runtime.NumCPU() {
		wg.Go(func() {
			for range iterations {
				scanner := sp.Get(rules)
				_, _ = scanner.Scan([]byte("test data"))
				sp.Put(scanner)
			}
		})
	}

	wg.Wait()
}

func TestScannerPoolGetDrawsFromPool(t *testing.T) {
	t.Parallel()
	rules, err := yarax.Compile("rule pool_draw { condition: true }")
	if err != nil {
		t.Fatalf("compile test rule: %v", err)
	}
	t.Cleanup(rules.Destroy)

	sp := NewScannerPool(rules, 1)
	defer sp.Close()

	scanner := sp.Get(rules)
	if got := len(sp.scanners); got != 0 {
		t.Errorf("pooled scanners after Get: got = %d, want = 0", got)
	}
	sp.Put(scanner)
	if got := len(sp.scanners); got != 1 {
		t.Errorf("pooled scanners after Put: got = %d, want = 1", got)
	}
}
