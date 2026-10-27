// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package action

import (
	"math"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"golang.org/x/sys/unix"
)

const (
	cgroupDir = "/sys/fs/cgroup"
	// cgroupV2MemoryMax and cgroupV1MemoryLimit hold the memory limit of a
	// cgroup under cgroup v2 and v1: memory.max in the cgroup's directory
	// beneath cgroupDir, and memory.limit_in_bytes in its directory beneath
	// cgroupDir's memory hierarchy.
	cgroupV2MemoryMax   = "memory.max"
	cgroupV1MemoryLimit = "memory/memory.limit_in_bytes"
)

// memoryLimit returns the memory the process may use: the smaller of
// physical memory and its cgroup limit, or 0 when neither is known.
func memoryLimit() int64 {
	// An unreadable /proc/self/cgroup leaves the cgroup at cgroupDir itself,
	// as a container with its own cgroup namespace sees it.
	self, _ := file.ReadFileIn("/proc/self", "cgroup")
	return memoryLimitFrom(physicalMemory(), cgroupDir, self)
}

// memoryLimitFrom returns the smaller of physical, 0 when unknown, and the
// limit of the cgroup that self, the contents of /proc/self/cgroup, names
// beneath dir.
func memoryLimitFrom(physical int64, dir string, self []byte) int64 {
	if cg, ok := cgroupMemoryLimit(dir, self); ok && (physical == 0 || cg < physical) {
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

// cgroupMemoryLimit returns the memory limit of the process's cgroup beneath
// dir: the smallest limit set on the cgroup that self, the contents of
// /proc/self/cgroup, names, or on any of its ancestors, since a cgroup's
// memory counts against each. The cgroup v2 memory.max files decide when any
// exists; otherwise the cgroup v1 memory.limit_in_bytes files do. The value
// "max", and cgroup v1's near-2^63 stand-in for no limit, report none.
func cgroupMemoryLimit(dir string, self []byte) (int64, bool) {
	v2, v1 := selfCgroups(self)
	if limit, found, ok := smallestLimit(dir, v2, "", cgroupV2MemoryMax); found {
		return limit, ok
	}
	limit, _, ok := smallestLimit(dir, v1, path.Dir(cgroupV1MemoryLimit), path.Base(cgroupV1MemoryLimit))
	return limit, ok
}

// selfCgroups returns the cgroup v2 path and the cgroup v1 memory controller
// path that self, the contents of /proc/self/cgroup, holds, or "" for each
// it does not.
func selfCgroups(self []byte) (string, string) {
	var v2, v1 string
	for line := range strings.Lines(string(self)) {
		id, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		controllers, cg, ok := strings.Cut(rest, ":")
		switch {
		case !ok:
		case id == "0" && controllers == "":
			v2 = cg
		case slices.Contains(strings.Split(controllers, ","), "memory"):
			v1 = cg
		}
	}
	return v2, v1
}

// smallestLimit returns the smallest limit in the files named name in the
// directory of cgroup cg, beneath hierarchy in dir, and in the directories
// of its ancestors, whether any such file exists, and whether one sets a
// limit. A cgroup path that leads outside the hierarchy, as for a process
// outside the cgroup namespace's root, is read as its root.
func smallestLimit(dir, cg, hierarchy, name string) (int64, bool, bool) {
	rel := strings.TrimPrefix(path.Clean("/"+cg), "/")
	if rel == "" {
		rel = "."
	}
	var limit int64
	var found, ok bool
	for {
		raw, err := file.ReadFileIn(dir, path.Join(hierarchy, rel, name))
		if err == nil {
			found = true
			v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
			if err == nil && v > 0 && v < 1<<62 && (!ok || v < limit) {
				limit, ok = v, true
			}
		}
		if rel == "." {
			return limit, found, ok
		}
		rel = path.Dir(rel)
	}
}
