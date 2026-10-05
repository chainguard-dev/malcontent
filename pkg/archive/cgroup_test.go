// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestCPUQuotaSignatureSane(t *testing.T) {
	t.Parallel()
	n, ok := CPUQuota()
	if ok && n <= 0 {
		t.Fatalf("CPUQuota returned ok=true with non-positive count %d", n)
	}
	if !ok && n != 0 {
		t.Fatalf("CPUQuota returned ok=false but non-zero count %d", n)
	}
}

func TestEffectiveMaxConcurrencyClamping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		quotaCPUs   int
		quotaOK     bool
		gomaxprocs  int
		configured  int
		expectedMin int
		expectedMax int
	}{
		{
			name:        "cgroup_overrides_high_config",
			quotaCPUs:   2,
			quotaOK:     true,
			gomaxprocs:  32,
			configured:  16,
			expectedMin: 2,
			expectedMax: 2,
		},
		{
			name:        "config_overrides_cgroup_when_lower",
			quotaCPUs:   8,
			quotaOK:     true,
			gomaxprocs:  32,
			configured:  4,
			expectedMin: 4,
			expectedMax: 4,
		},
		{
			name:        "gomaxprocs_caps_when_smallest",
			quotaCPUs:   16,
			quotaOK:     true,
			gomaxprocs:  4,
			configured:  16,
			expectedMin: 4,
			expectedMax: 4,
		},
		{
			name:        "floor_one_when_zero_configured",
			quotaCPUs:   0,
			quotaOK:     false,
			gomaxprocs:  8,
			configured:  0,
			expectedMin: 1,
			expectedMax: 1,
		},
		{
			name:        "no_cgroup_uses_min_of_remaining",
			quotaCPUs:   0,
			quotaOK:     false,
			gomaxprocs:  4,
			configured:  16,
			expectedMin: 4,
			expectedMax: 4,
		},
		{
			name:        "negative_configured_floors_to_one",
			quotaCPUs:   0,
			quotaOK:     false,
			gomaxprocs:  8,
			configured:  -5,
			expectedMin: 1,
			expectedMax: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := effectiveConcurrencyFor(tc.quotaCPUs, tc.quotaOK, tc.gomaxprocs, tc.configured)
			if got < tc.expectedMin || got > tc.expectedMax {
				t.Fatalf("effectiveConcurrencyFor(%d,%t,%d,%d) = %d; want in [%d,%d]",
					tc.quotaCPUs, tc.quotaOK, tc.gomaxprocs, tc.configured, got,
					tc.expectedMin, tc.expectedMax)
			}
			if got < 1 {
				t.Fatalf("floor violated: got %d", got)
			}
		})
	}
}

func TestEffectiveMaxConcurrencyMatchesPublic(t *testing.T) {
	t.Parallel()
	configured := 32
	got := EffectiveMaxConcurrency(configured)
	if got < 1 {
		t.Fatalf("EffectiveMaxConcurrency(%d) = %d; want >=1", configured, got)
	}
	if got > runtime.GOMAXPROCS(0) {
		t.Fatalf("EffectiveMaxConcurrency(%d) = %d; exceeds GOMAXPROCS %d",
			configured, got, runtime.GOMAXPROCS(0))
	}
}

func TestGlobalExtractionSemaphoreUnblocks(t *testing.T) {
	t.Parallel()

	weight := 2
	sem := newExtractionSemaphoreForTest(weight)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Fill the semaphore to capacity.
	for i := range weight {
		if err := sem.Acquire(ctx, 1); err != nil {
			t.Fatalf("Acquire %d failed: %v", i, err)
		}
	}

	// A full semaphore admits no further permit.
	if sem.TryAcquire(1) {
		t.Fatal("(cap+1)th Acquire: got = acquired, want = blocked while semaphore full")
	}

	// A waiting acquirer proceeds once a permit is released.
	acquired := make(chan struct{})
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	wg.Go(func() {
		if err := sem.Acquire(ctx, 1); err != nil {
			return
		}
		close(acquired)
		sem.Release(1)
	})

	sem.Release(1)

	select {
	case <-acquired:
	case <-ctx.Done():
		t.Fatal("(cap+1)th Acquire: got = still blocked, want = unblocked after Release")
	}

	// Drain remaining permit.
	sem.Release(1)
}

func TestExtractionSemaphoreLazyInit(t *testing.T) {
	t.Parallel()
	sem := extractionSemaphore()
	if sem == nil {
		t.Fatal("extractionSemaphore() returned nil")
	}
	// Repeat call returns the same instance.
	sem2 := extractionSemaphore()
	if sem != sem2 {
		t.Fatal("extractionSemaphore() not memoized")
	}
}
