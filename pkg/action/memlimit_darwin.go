// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package action

import (
	"math"

	"golang.org/x/sys/unix"
)

// memoryLimit returns the system's physical memory, or 0 when unknown.
func memoryLimit() int64 {
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return int64(min(total, math.MaxInt64)) // #nosec G115 -- clamped to MaxInt64 first
}
