// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// Constants used across strings_test and fuzz_test.
const (
	numGoroutines = 1000
	numIterations = 1000
	numOps        = 1000
	numCopies     = 1000
)

// StringDataPointer returns the pointer to the underlying data of a string.
// Used for verifying that interned strings share the same backing array.
func StringDataPointer(s string) uintptr {
	return (*[2]uintptr)(unsafe.Pointer(&s))[0]
}

func TestNewStringPool(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()
	if pool == nil {
		t.Fatal("NewStringPool() returned nil")
	}
}

func TestStringPoolInternBasic(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()

	s1 := pool.Intern("hello")
	if s1 != "hello" {
		t.Errorf("intern returned %q, want %q", s1, "hello")
	}

	s2 := pool.Intern("hello")
	if s2 != "hello" {
		t.Errorf("intern returned %q, want %q", s2, "hello")
	}

	if StringDataPointer(s1) != StringDataPointer(s2) {
		t.Error("intern did not return the same string instance for identical strings")
	}
}

func TestStringPoolInternDifferentStrings(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()

	s1 := pool.Intern("hello")
	s2 := pool.Intern("world")

	if s1 == s2 {
		t.Error("different strings should not be equal")
	}
	if StringDataPointer(s1) == StringDataPointer(s2) {
		t.Error("different strings should have different data pointers")
	}
}

func TestStringPoolInternEmptyString(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()

	s1 := pool.Intern("")
	s2 := pool.Intern("")

	if s1 != "" || s2 != "" {
		t.Error("empty string interning failed")
	}
}

func TestStringPoolInternDynamicStrings(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()

	base := "test"
	d1 := base + "123"
	d2 := base + "123"

	s1 := pool.Intern(d1)
	s2 := pool.Intern(d2)

	if s1 != "test123" || s2 != "test123" {
		t.Errorf("dynamic string interning failed: s1=%q, s2=%q", s1, s2)
	}

	if StringDataPointer(s1) != StringDataPointer(s2) {
		t.Error("dynamically created identical strings should share backing data after interning")
	}
}

func TestStringPoolClear(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()

	_ = pool.Intern("hello")
	_ = pool.Intern("world")

	pool.clear()

	s := pool.Intern("hello")
	if s != "hello" {
		t.Errorf("intern after clear returned %q, want %q", s, "hello")
	}
}

// TestStringPoolConcurrent tests that the StringPool is safe for concurrent access.
func TestStringPoolConcurrent(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	strings := []string{"apple", "banana", "cherry", "date", "elderberry"}

	for range numGoroutines {
		wg.Go(func() {
			defer wg.Done()
			for range numIterations {
				for _, s := range strings {
					interned := pool.Intern(s)
					if interned != s {
						t.Errorf("intern returned %q, want %q", interned, s)
					}
				}
			}
		})
	}

	wg.Wait()
}

// TestStringPoolConcurrentSamePointers verifies that
// concurrent interning returns the same pointer for identical strings.
func TestStringPoolConcurrentSamePointers(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()

	const testString = "concurrent-test-string"

	pointers := make(chan uintptr, numGoroutines)
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	start := make(chan struct{})

	for range numGoroutines {
		wg.Go(func() {
			defer wg.Done()
			<-start
			cpy := testString
			interned := pool.Intern(cpy)
			pointers <- StringDataPointer(interned)
		})
	}

	close(start)
	wg.Wait()
	close(pointers)

	var firstPtr uintptr
	first := true
	for ptr := range pointers {
		if first {
			firstPtr = ptr
			first = false
		} else if ptr != firstPtr {
			t.Errorf("concurrent interning returned different pointers: %v vs %v", firstPtr, ptr)
		}
	}
}

// TestStringPoolAtomic tests that the interning is resistant to TOCTOU scenarios.
func TestStringPoolAtomic(t *testing.T) {
	t.Parallel()

	for iter := range numIterations {
		pool := NewStringPool()
		testStr := fmt.Sprintf("race-test-%d", iter)

		results := make([]string, numGoroutines)
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		start := make(chan struct{})

		for i := range numGoroutines {
			wg.Go(func() {
				defer wg.Done()
				<-start
				cpy := string([]byte(testStr))
				results[i] = pool.Intern(cpy)
			})
		}

		close(start)
		wg.Wait()

		firstPtr := StringDataPointer(results[0])
		for i, s := range results {
			if StringDataPointer(s) != firstPtr {
				t.Errorf("iteration %d: goroutine %d got different pointer: %v vs %v",
					iter, i, StringDataPointer(s), firstPtr)
			}
		}
	}
}

// TestStringPoolRaceCondition leverages -race to verify safety.
func TestStringPoolRaceCondition(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3)

	// Concurrent interning of identical strings
	for range numGoroutines {
		wg.Go(func() {
			defer wg.Done()
			for range numOps {
				pool.Intern("shared")
			}
		})
	}

	// Concurrent interning of unique strings
	for i := range numGoroutines {
		wg.Go(func() {
			defer wg.Done()
			for j := range numOps {
				pool.Intern(fmt.Sprintf("unique-%d-%d", i, j))
			}
		})
	}

	// Concurrent clear operations
	for range numGoroutines {
		wg.Go(func() {
			defer wg.Done()
			for range numOps {
				pool.clear()
			}
		})
	}

	wg.Wait()
}

// TestStringPoolMemoryDeduplication verifies that string interning
// reduces memory usage by sharing backing arrays.
func TestStringPoolMemoryDeduplication(t *testing.T) {
	t.Parallel()
	pool := NewStringPool()

	const testString = "this is a test string for deduplication"

	interned := make([]string, numCopies)
	for i := range numCopies {
		cpy := string([]byte(testString))
		interned[i] = pool.Intern(cpy)
	}

	firstPtr := StringDataPointer(interned[0])
	for i, s := range interned {
		if StringDataPointer(s) != firstPtr {
			t.Errorf("String %d has different backing data", i)
		}
	}
}

// TestContainsUnprintable tests the containsUnprintable function.
func TestContainsUnprintable(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"empty", []byte{}, false},
		{"printable ASCII", []byte("hello world"), false},
		{"all printable", []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), false},
		{"printable symbols", []byte("!@#$%^&*()_+-=[]{}|;':\",./<>?"), false},
		{"space", []byte(" "), false},
		{"tilde", []byte("~"), false},
		{"null byte", []byte{0x00}, true},
		{"tab", []byte{0x09}, true},
		{"newline", []byte{0x0a}, true},
		{"carriage return", []byte{0x0d}, true},
		{"control char", []byte{0x1f}, true},
		{"DEL", []byte{0x7f}, true},
		{"high bit", []byte{0x80}, true},
		{"0xFF", []byte{0xff}, true},
		{"mixed printable and unprintable", []byte("hello\x00world"), true},
		{"boundary low", []byte{31}, true},   // just below printable
		{"boundary high", []byte{127}, true}, // just above printable
		{"exactly 32", []byte{32}, false},    // space is printable
		{"exactly 126", []byte{126}, false},  // tilde is printable
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := containsUnprintable(tt.input)
			if got != tt.want {
				t.Errorf("containsUnprintable(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestStringPoolConcurrentStress is a stress test for concurrent access.
func TestStringPoolConcurrentStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}
	t.Parallel()

	pool := NewStringPool()

	var successCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := range numGoroutines {
		wg.Go(func() {
			defer wg.Done()
			for j := range numIterations {
				if j%2 == 0 {
					s := pool.Intern("shared-string")
					if s == "shared-string" {
						successCount.Add(1)
					}
				} else {
					s := pool.Intern(fmt.Sprintf("unique-%d-%d", i, j))
					if s != "" {
						successCount.Add(1)
					}
				}
			}
		})
	}

	wg.Wait()

	expectedCount := int64(numGoroutines * numIterations)
	if successCount.Load() != expectedCount {
		t.Errorf("Expected %d successful operations, got %d", expectedCount, successCount.Load())
	}
}

func BenchmarkStringPoolInternSame(b *testing.B) {
	pool := NewStringPool()
	testStr := "benchmark-test-string"

	// Pre-populate
	pool.Intern(testStr)

	for b.Loop() {
		pool.Intern(testStr)
	}
}

func BenchmarkStringPoolInternDifferent(b *testing.B) {
	pool := NewStringPool()
	strings := make([]string, 1000)
	for i := range strings {
		strings[i] = fmt.Sprintf("string-%d", i)
	}

	for b.Loop() {
		for _, s := range strings {
			pool.Intern(s)
		}
	}
}

func BenchmarkStringPoolInternConcurrent(b *testing.B) {
	pool := NewStringPool()
	strings := []string{"apple", "banana", "cherry", "date", "elderberry"}

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			pool.Intern(strings[i%len(strings)])
			i++
		}
	})
}

func BenchmarkContainsUnprintableValid(b *testing.B) {
	data := []byte("This is a test string with only printable characters 1234567890")
	for b.Loop() {
		containsUnprintable(data)
	}
}

func BenchmarkContainsUnprintableInvalid(b *testing.B) {
	data := []byte("This has a null\x00byte")
	for b.Loop() {
		containsUnprintable(data)
	}
}
