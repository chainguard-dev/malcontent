// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package action

import (
	"math"
	"strconv"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"golang.org/x/sys/unix"
)

const (
	cgroupDir = "/sys/fs/cgroup"
	// cgroupV2MemoryMax and cgroupV1MemoryLimit hold the memory limit of
	// the process's cgroup under cgroup v2 and v1, relative to cgroupDir.
	cgroupV2MemoryMax   = "memory.max"
	cgroupV1MemoryLimit = "memory/memory.limit_in_bytes"
)

// memoryLimit returns the memory the process may use: the smaller of
// physical memory and its cgroup limit, or 0 when neither is known.
func memoryLimit() int64 {
	return memoryLimitFrom(physicalMemory(), cgroupDir)
}

// memoryLimitFrom returns the smaller of physical, 0 when unknown, and the
// limit of the cgroup files beneath dir.
func memoryLimitFrom(physical int64, dir string) int64 {
	if cg, ok := cgroupMemoryLimit(dir); ok && (physical == 0 || cg < physical) {
		return cg
	}
	return physical
}

// physicalMemory returns the system's total memory, or 0 when unknown.
func physicalMemory() int64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}
	return sysinfoMemory(uint64(info.Totalram), uint64(info.Unit)) //nolint:unconvert // Totalram is 32 bits wide on 32-bit platforms
}

// sysinfoMemory returns totalram memory units of unit bytes, or MaxInt64
// when that does not fit.
func sysinfoMemory(totalram, unit uint64) int64 {
	if unit != 0 && totalram > math.MaxInt64/unit {
		return math.MaxInt64
	}
	return int64(totalram * unit) // #nosec G115 -- bounded by MaxInt64 above
}

// cgroupMemoryLimit returns the memory limit in the cgroup v2 memory.max
// beneath dir or, when that file is absent, in the cgroup v1
// memory.limit_in_bytes. The value "max", and cgroup v1's near-2^63 stand-in
// for no limit, report none.
func cgroupMemoryLimit(dir string) (int64, bool) {
	for _, name := range []string{cgroupV2MemoryMax, cgroupV1MemoryLimit} {
		raw, err := file.ReadFileIn(dir, name)
		if err != nil {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil || v <= 0 || v >= 1<<62 {
			return 0, false
		}
		return v, true
	}
	return 0, false
}
