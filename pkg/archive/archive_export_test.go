// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import "golang.org/x/sync/semaphore"

// newExtractionSemaphoreForTest is a hook for unit tests that need to exercise
// the semaphore's blocking behavior at a controlled capacity.
func newExtractionSemaphoreForTest(n int) *semaphore.Weighted {
	if n < 1 {
		n = 1
	}
	return semaphore.NewWeighted(int64(n))
}
