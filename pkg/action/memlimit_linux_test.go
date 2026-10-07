// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package action

import (
	"math"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// cgroupTestDir returns a directory holding memory.max with v2, and
// memory/memory.limit_in_bytes with v1; an empty value leaves its file out.
func cgroupTestDir(t *testing.T, v2, v1 string) string {
	t.Helper()
	dir := t.TempDir()
	if v2 != "" {
		if err := file.WriteFileIn(dir, cgroupV2MemoryMax, []byte(v2), 0o600); err != nil {
			t.Fatalf("write %s: %v", cgroupV2MemoryMax, err)
		}
	}
	if v1 != "" {
		if err := file.MkdirAllIn(dir, "memory", 0o700); err != nil {
			t.Fatalf("mkdir memory: %v", err)
		}
		if err := file.WriteFileIn(dir, cgroupV1MemoryLimit, []byte(v1), 0o600); err != nil {
			t.Fatalf("write %s: %v", cgroupV1MemoryLimit, err)
		}
	}
	return dir
}

func TestCgroupMemoryLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		v2, v1 string // file contents; "" leaves the file absent
		want   int64
		wantOK bool
	}{
		{name: "cgroup v2 limit", v2: "8589934592\n", want: 8 << 30, wantOK: true},
		{name: "cgroup v2 without a limit", v2: "max\n", v1: "1073741824\n"},
		{name: "cgroup v1 limit when v2 is absent", v1: "1073741824\n", want: 1 << 30, wantOK: true},
		{name: "cgroup v1 stand-in for no limit", v1: "9223372036854771712\n"},
		{name: "limit of 2^62 is no limit", v2: "4611686018427387904\n"},
		{name: "limit just below 2^62", v2: "4611686018427387903\n", want: 1<<62 - 1, wantOK: true},
		{name: "one-byte limit", v2: "1\n", want: 1, wantOK: true},
		{name: "zero limit is no limit", v2: "0\n"},
		{name: "unreadable value is no limit", v2: "lots\n"},
		{name: "no cgroup files"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := cgroupMemoryLimit(cgroupTestDir(t, tt.v2, tt.v1))
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("cgroupMemoryLimit: got = (%d, %v), want = (%d, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestMemoryLimitFrom(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		physical int64
		cgroup   string // memory.max contents; "" leaves it absent
		want     int64
	}{
		{name: "cgroup limit below physical memory", physical: 16 << 30, cgroup: "8589934592\n", want: 8 << 30},
		{name: "cgroup limit above physical memory", physical: 16 << 30, cgroup: "34359738368\n", want: 16 << 30},
		{name: "cgroup limit without known physical memory", physical: 0, cgroup: "1073741824\n", want: 1 << 30},
		{name: "physical memory without a cgroup limit", physical: 16 << 30, cgroup: "max\n", want: 16 << 30},
		{name: "physical memory without cgroup files", physical: 16 << 30, want: 16 << 30},
		{name: "nothing known", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := memoryLimitFrom(tt.physical, cgroupTestDir(t, tt.cgroup, "")); got != tt.want {
				t.Errorf("memoryLimitFrom: got = %d, want = %d", got, tt.want)
			}
		})
	}
}

func TestSysinfoMemory(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		totalram, unit uint64
		want           int64
	}{
		{name: "units of one byte", totalram: 4096, unit: 1, want: 4096},
		{name: "units of several bytes", totalram: 1000, unit: 4, want: 4000},
		{name: "no units", totalram: 1000, unit: 0, want: 0},
		{name: "largest total that fits", totalram: math.MaxInt64 / 2, unit: 2, want: math.MaxInt64 - 1},
		{name: "total beyond int64 saturates", totalram: math.MaxInt64/2 + 1, unit: 2, want: math.MaxInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sysinfoMemory(tt.totalram, tt.unit); got != tt.want {
				t.Errorf("sysinfoMemory(%d, %d): got = %d, want = %d", tt.totalram, tt.unit, got, tt.want)
			}
		})
	}
}

func TestMemoryLimitIsAtMostPhysicalMemory(t *testing.T) {
	t.Parallel()
	physical := physicalMemory()
	if physical <= 0 {
		t.Fatalf("physicalMemory: got = %d, want the system's memory", physical)
	}
	if got := memoryLimit(); got <= 0 || got > physical {
		t.Errorf("memoryLimit: got = %d, want between 1 and %d", got, physical)
	}
}
