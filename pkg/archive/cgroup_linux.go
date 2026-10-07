// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package archive

import (
	"strconv"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// cgroupDir holds the cgroup CPU limit files, named relative to it.
const (
	cgroupDir             = "/sys/fs/cgroup"
	cgroupV2CPUMaxName    = "cpu.max"
	cgroupV1CPUQuotaName  = "cpu/cpu.cfs_quota_us"
	cgroupV1CPUPeriodName = "cpu/cpu.cfs_period_us"
)

// CPUQuota returns the cgroup-derived CPU ceiling for this process, expressed
// as a count of logical CPUs (ceil(quota/period), floored at 1). The second
// return is false when no cgroup ceiling applies.
func CPUQuota() (int, bool) {
	if n, ok := readCgroupV2(cgroupDir, cgroupV2CPUMaxName); ok {
		return n, true
	}
	return readCgroupV1(cgroupDir, cgroupV1CPUQuotaName, cgroupV1CPUPeriodName)
}

// readCgroupV2 parses the "<quota> <period>" form of name beneath dir. The
// literal "max" in the quota slot disables the ceiling.
func readCgroupV2(dir, name string) (int, bool) {
	raw, err := file.ReadFileIn(dir, name)
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

// readCgroupV1 divides the quota in quotaName by the period in periodName,
// both beneath dir.
func readCgroupV1(dir, quotaName, periodName string) (int, bool) {
	quota, ok := readIntFile(dir, quotaName)
	if !ok || quota <= 0 {
		return 0, false
	}
	period, ok := readIntFile(dir, periodName)
	if !ok || period <= 0 {
		return 0, false
	}
	return ceilDiv(quota, period), true
}

// readIntFile parses the integer held in name beneath dir.
func readIntFile(dir, name string) (int64, bool) {
	raw, err := file.ReadFileIn(dir, name)
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
