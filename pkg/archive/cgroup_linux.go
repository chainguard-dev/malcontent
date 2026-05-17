// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package archive

import (
	"os"
	"strconv"
	"strings"
)

const (
	cgroupV2CPUMaxPath    = "/sys/fs/cgroup/cpu.max"
	cgroupV1CPUQuotaPath  = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
	cgroupV1CPUPeriodPath = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
)

// CPUQuota returns the cgroup-derived CPU ceiling for this process, expressed
// as a count of logical CPUs (ceil(quota/period), floored at 1). The second
// return is false when no cgroup ceiling applies.
func CPUQuota() (int, bool) {
	if n, ok := readCgroupV2(cgroupV2CPUMaxPath); ok {
		return n, true
	}
	return readCgroupV1(cgroupV1CPUQuotaPath, cgroupV1CPUPeriodPath)
}

// readCgroupV2 parses the "<quota> <period>" form. The literal "max" in the
// quota slot disables the ceiling.
func readCgroupV2(path string) (int, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(strings.TrimSpace(string(raw)))
	if len(fields) != 2 {
		return 0, false
	}
	if fields[0] == "max" {
		return 0, false
	}
	quota, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || quota <= 0 {
		return 0, false
	}
	period, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || period <= 0 {
		return 0, false
	}
	return ceilDiv(quota, period), true
}

func readCgroupV1(quotaPath, periodPath string) (int, bool) {
	quota, ok := readIntFile(quotaPath)
	if !ok || quota <= 0 {
		return 0, false
	}
	period, ok := readIntFile(periodPath)
	if !ok || period <= 0 {
		return 0, false
	}
	return ceilDiv(quota, period), true
}

func readIntFile(path string) (int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func ceilDiv(a, b int64) int {
	n := (a + b - 1) / b
	if n < 1 {
		return 1
	}
	return int(n)
}
