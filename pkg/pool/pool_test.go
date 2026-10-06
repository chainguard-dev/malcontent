// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"math"
	"runtime"
	"sync"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/malcontent/pkg/file"
)

func TestNewBufferPool(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		count int
	}{
		{"zero count", 0},
		{"single buffer", 1},
		{"multiple buffers", 5},
		{"many buffers", 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bp := NewBufferPool(tt.count)
			if bp == nil {
				t.Fatal("NewBufferPool returned nil")
			}

			// Verify we can get buffers
			buf := bp.Get(file.DefaultPoolBuffer)
			if buf == nil {
				t.Error("Get returned nil buffer")
			}
			if cap(buf) < int(file.DefaultPoolBuffer) {
				t.Errorf("buffer capacity = %d, want >= %d", cap(buf), file.DefaultPoolBuffer)
			}
		})
	}
}

func TestBufferPoolGet(t *testing.T) {
	t.Parallel()
	bp := NewBufferPool(2)

	tests := []struct {
		name     string
		size     int64
		wantSize int64
	}{
		{"negative size", -1, 1},
		{"zero size", 0, 1},
		{"small size", 100, 100},
		{"default size", file.DefaultPoolBuffer, file.DefaultPoolBuffer},
		{"large size", file.MaxPoolBuffer, file.MaxPoolBuffer},
		{"very large size", file.MaxPoolBuffer * 2, file.MaxPoolBuffer * 2},
		{"max int64", math.MaxInt64, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			buf := bp.Get(tt.size)
			if buf == nil {
				t.Fatal("Get returned nil")
			}

			if int64(len(buf)) != tt.wantSize {
				t.Errorf("buffer length = %d, want %d", len(buf), tt.wantSize)
			}

			if int64(cap(buf)) < tt.wantSize {
				t.Errorf("buffer capacity = %d, want >= %d", cap(buf), tt.wantSize)
			}

			// Return buffer to pool
			bp.Put(buf)
		})
	}
}

func TestBufferPoolGetExceedsCapacity(t *testing.T) {
	t.Parallel()
	bp := NewBufferPool(1)

	// Get a small buffer
	buf1 := bp.Get(1024)
	if len(buf1) != 1024 {
		t.Fatalf("first Get returned buffer of length %d, want 1024", len(buf1))
	}

	// Return it
	bp.Put(buf1)

	// Request a larger buffer - should get new buffer since capacity is insufficient
	buf2 := bp.Get(file.MaxPoolBuffer * 2)
	if len(buf2) != int(file.MaxPoolBuffer*2) {
		t.Errorf("second Get returned buffer of length %d, want %d", len(buf2), file.MaxPoolBuffer*2)
	}
}

func TestBufferPoolPut(t *testing.T) {
	t.Parallel()
	bp := NewBufferPool(2)

	t.Run("put nil buffer", func(t *testing.T) {
		t.Parallel()
		// Should not panic
		bp.Put(nil)
	})

	t.Run("put normal buffer", func(t *testing.T) {
		t.Parallel()
		buf := bp.Get(file.DefaultPoolBuffer)
		// Modify buffer
		for i := range buf {
			buf[i] = byte(i % 256)
		}

		bp.Put(buf)

		// Get buffer again and verify it was cleared
		buf2 := bp.Get(file.DefaultPoolBuffer)
		for i := range buf2 {
			if buf2[i] != 0 {
				t.Errorf("buffer not cleared at index %d: got %d, want 0", i, buf2[i])
				break
			}
		}
	})

	t.Run("put buffer exceeding max pool size", func(t *testing.T) {
		t.Parallel()
		// Create a very large buffer
		largeBuf := make([]byte, file.MaxPoolBuffer*2)
		bp.Put(largeBuf)

		// Get a normal buffer - should not get the large one back
		buf := bp.Get(file.DefaultPoolBuffer)
		if cap(buf) > int(file.MaxPoolBuffer*2) {
			t.Error("got unexpectedly large buffer from pool")
		}
	})
}

func TestBufferPoolConcurrency(t *testing.T) {
	t.Parallel()
	bp := NewBufferPool(5)
	var wg sync.WaitGroup
	iterations := 100

	// Run multiple goroutines getting and putting buffers
	for range 10 {
		wg.Go(func() {
			for range iterations {
				buf := bp.Get(file.DefaultPoolBuffer)
				// Simulate work
				for k := range buf {
					buf[k] = byte(k % 256)
				}
				bp.Put(buf)
			}
		})
	}

	wg.Wait()
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

func TestScannerPoolClose(t *testing.T) {
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

	sp := NewScannerPool(rules, 2)

	sp.Close()
	sp.Close() // Should not panic
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

func TestBufferPoolGetReusesSufficientCapacity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		size      int64
		wantReuse bool
	}{
		{"request below pooled capacity reuses the buffer", 16, true},
		{"request equal to pooled capacity reuses the buffer", 64, true},
		{"request above pooled capacity allocates a new buffer", 65, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pooled := make([]byte, 8, 64)
			bp := &BufferPool{}
			bp.pool.New = func() any { return &pooled }

			got := bp.Get(tt.size)
			if int64(len(got)) != tt.size {
				t.Fatalf("buffer length: got = %d, want = %d", len(got), tt.size)
			}
			if reused := &got[0] == &pooled[0]; reused != tt.wantReuse {
				t.Errorf("reused pooled buffer: got = %v, want = %v", reused, tt.wantReuse)
			}
		})
	}
}

func TestBufferPoolPutClearsCallerBuffer(t *testing.T) {
	t.Parallel()
	bp := NewBufferPool(0)
	buf := []byte{1, 2, 3, 4}

	bp.Put(buf)

	for i, b := range buf {
		if b != 0 {
			t.Errorf("buf[%d]: got = %d, want = 0", i, b)
		}
	}
}

func TestBufferPoolPutRetainsBuffersUpToMaxPoolBuffer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		capacity   int64
		wantPooled bool
	}{
		{"default capacity is retained", file.DefaultPoolBuffer, true},
		{"capacity equal to MaxPoolBuffer is retained", file.MaxPoolBuffer, true},
		{"capacity above MaxPoolBuffer is dropped", file.MaxPoolBuffer + 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bp := &BufferPool{}
			bp.pool.New = func() any {
				fresh := make([]byte, 1)
				return &fresh
			}

			if got := smallPoolReturnsBuffer(bp, make([]byte, tt.capacity)); got != tt.wantPooled {
				t.Errorf("buffer retained by pool: got = %v, want = %v", got, tt.wantPooled)
			}
		})
	}
}

// smallPoolReturnsBuffer reports whether bp hands buf back from Get after Put.
// sync.Pool may discard any single Put (the race detector does so at random),
// so a retained buffer is detected by retrying, while a dropped buffer never
// comes back and the New fallback supplies a distinct one each time.
func smallPoolReturnsBuffer(bp *BufferPool, buf []byte) bool {
	for range 64 {
		bp.Put(buf)
		if got := bp.Get(1); &got[0] == &buf[0] {
			return true
		}
	}
	return false
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
