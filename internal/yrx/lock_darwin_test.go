// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package yrx

import "testing"

// TestLockHoldsTheMutex checks that lock takes the mutex that runs calls one
// at a time and unlock releases it. Every call that registers or deregisters
// rules runs between the two (TestCallsRunInsideTheLock), so no two run at
// once. It must not call t.Parallel, since it holds the mutex.
func TestLockHoldsTheMutex(t *testing.T) {
	lock()
	if mu.TryLock() {
		mu.Unlock()
		t.Error("lock: the mutex is free while held")
	}
	unlock()
	if !mu.TryLock() {
		t.Fatal("unlock: the mutex is still held")
	}
	mu.Unlock()
}
