// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/puzpuzpuz/xsync/v4"
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

// newIsolatedPool returns a StringPool that does not share state with the
// process-wide singleton. Tests asserting backing-array identity use it so
// the assertion is unaffected by the singleton's bounded resets, which can
// fire when other parallel tests intern large numbers of distinct strings.
func newIsolatedPool() *StringPool {
	return &StringPool{strings: xsync.NewMap[string, string]()}
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
	pool := newIsolatedPool()

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
	pool := newIsolatedPool()

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

// TestStringPoolBounded verifies the interned set does not grow without
// bound: interning more distinct values than maxInternedStrings resets the
// pool so its size stays within the cap rather than accumulating every
// distinct string across the process lifetime. An isolated pool keeps the
// count deterministic, independent of the shared singleton other parallel
// tests exercise.
func TestStringPoolBounded(t *testing.T) {
	t.Parallel()
	pool := newIsolatedPool()

	const distinct = maxInternedStrings * 2
	for i := range distinct {
		s := pool.Intern(fmt.Sprintf("bounded-%d", i))
		if want := fmt.Sprintf("bounded-%d", i); s != want {
			t.Fatalf("intern returned %q for index %d, want %q", s, i, want)
		}
		// The clear fires after the entry that hits the cap is already
		// stored, so the map momentarily holds maxInternedStrings entries
		// before dropping to zero. Allow a small margin for concurrency
		// artifacts in xsync.Map.Size().
		if got := pool.strings.Size(); got > maxInternedStrings+1 {
			t.Fatalf("pool size %d exceeded cap %d at index %d", got, maxInternedStrings, i)
		}
	}

	// Interning twice the cap in distinct values must not retain them all.
	if got := pool.strings.Size(); got >= distinct {
		t.Fatalf("pool size %d did not stay bounded below %d distinct strings", got, distinct)
	}
}

// TestStringPoolBoundedAcrossCycles verifies that repeated batches of
// distinct strings keep the interned set bounded rather than accumulating
// every string seen across batches.
func TestStringPoolBoundedAcrossCycles(t *testing.T) {
	t.Parallel()
	pool := newIsolatedPool()

	const (
		cycles   = 4
		perCycle = maxInternedStrings
	)
	for c := range cycles {
		for j := range perCycle {
			pool.Intern(fmt.Sprintf("cycle-%d-%d", c, j))
		}
		if got := pool.strings.Size(); got > maxInternedStrings+1 {
			t.Fatalf("after cycle %d, pool size %d exceeded cap %d", c, got, maxInternedStrings)
		}
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
	pool := newIsolatedPool()

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
		pool := newIsolatedPool()
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

	// Concurrent interning of identical strings
	for range numGoroutines {
		wg.Go(func() {
			for range numOps {
				pool.Intern("shared")
			}
		})
	}

	// Concurrent interning of unique strings
	for i := range numGoroutines {
		wg.Go(func() {
			for j := range numOps {
				pool.Intern(fmt.Sprintf("unique-%d-%d", i, j))
			}
		})
	}

	// Use a small number of goroutines to exercise the race detector without triggering
	// resize contention in xsync.Map.
	for range 10 {
		wg.Go(func() {
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
	pool := newIsolatedPool()

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

// TestNewStringPoolSingleton verifies NewStringPool returns the same
// process-wide instance on successive calls.
func TestNewStringPoolSingleton(t *testing.T) {
	t.Parallel()

	p1 := NewStringPool()
	p2 := NewStringPool()
	if p1 != p2 {
		t.Errorf("expected pointer-equal pools, got distinct instances: %p vs %p", p1, p2)
	}
}

// TestNewStringPoolSingletonParallel verifies that concurrent callers
// of NewStringPool all observe the same pointer — the once-value init
// is race-free under contention.
func TestNewStringPoolSingletonParallel(t *testing.T) {
	t.Parallel()

	const parallelism = 256
	pointers := make([]*StringPool, parallelism)

	var wg sync.WaitGroup
	wg.Add(parallelism)
	start := make(chan struct{})
	for i := range parallelism {
		wg.Go(func() {
			defer wg.Done()
			<-start
			pointers[i] = NewStringPool()
		})
	}
	close(start)
	wg.Wait()

	first := pointers[0]
	for i, p := range pointers {
		if p != first {
			t.Errorf("goroutine %d observed pool %p, want %p", i, p, first)
		}
	}
}

// TestNewStringPoolSingletonSharesState verifies that two references
// returned by NewStringPool see the same interned strings — proves
// the underlying state is shared, not merely the pointer.
func TestNewStringPoolSingletonSharesState(t *testing.T) {
	t.Parallel()

	p1 := NewStringPool()
	p2 := NewStringPool()

	// Distinct heap allocations of the same bytes so identity is
	// established by the pool, not by the literal pool of the linker.
	a := string([]byte("singleton-shared-state-marker"))
	b := string([]byte("singleton-shared-state-marker"))

	s1 := p1.Intern(a)
	s2 := p2.Intern(b)

	if StringDataPointer(s1) != StringDataPointer(s2) {
		t.Errorf("interning the same value through two NewStringPool() references returned different backing pointers: %v vs %v",
			StringDataPointer(s1), StringDataPointer(s2))
	}
}
