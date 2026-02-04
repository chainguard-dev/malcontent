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
	bp := NewBufferPool(2)

	t.Run("put nil buffer", func(_ *testing.T) {
		// Should not panic
		bp.Put(nil)
	})

	t.Run("put normal buffer", func(t *testing.T) {
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

func TestBufferPoolConcurrency(_ *testing.T) {
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
	defer rules.Destroy()

	tests := []struct {
		name  string
		count int
	}{
		{"single scanner", 1},
		{"multiple scanners", 4},
		{"moderate number of scanners", 16},
		{"large number of scanners", 1024},
		{"unreasonable number of scanners", 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := NewScannerPool(rules, tt.count)
			if sp == nil {
				t.Fatal("NewScannerPool returned nil")
			}
			defer sp.Close()

			scanner := sp.Get(rules)
			if scanner == nil {
				t.Error("Get returned nil scanner")
			}
			sp.Put(scanner)
		})
	}
}

func TestScannerPoolGet(t *testing.T) {
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

	t.Run("get from pool", func(t *testing.T) {
		sp := NewScannerPool(rules, 2)
		defer sp.Close()

		scanner := sp.Get(rules)
		if scanner == nil {
			t.Fatal("Get returned nil")
		}

		sp.Put(scanner)
	})

	t.Run("get from nil pool", func(t *testing.T) {
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
	defer sp.Close()

	t.Run("put nil scanner", func(_ *testing.T) {
		sp.Put(nil)
	})

	t.Run("put valid scanner", func(t *testing.T) {
		s1 := sp.Get(rules)
		sp.Put(s1)

		s2 := sp.Get(rules)
		if s2 == nil {
			t.Error("failed to get scanner back from pool")
		}
		sp.Put(s2)
	})

	t.Run("fill pool", func(_ *testing.T) {
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
