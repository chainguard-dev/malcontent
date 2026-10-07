// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package archive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// streamsCgroupFile writes content to name beneath dir, creating its parent
// directories, or leaves it absent when missing is set.
func streamsCgroupFile(t *testing.T, dir, name, content string, missing bool) {
	t.Helper()
	if missing {
		return
	}
	if parent := filepath.Dir(name); parent != "." {
		if err := file.MkdirAllIn(dir, parent, 0o700); err != nil {
			t.Fatalf("create %s: %v", parent, err)
		}
	}
	if err := file.WriteFileIn(dir, name, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestReadCgroupV2CPUMax(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		missing bool
		wantN   int
		wantOK  bool
	}{
		{name: "quota twice the period is two CPUs", content: "200000 100000\n", wantN: 2, wantOK: true},
		{name: "fractional quota rounds up", content: "150000 100000", wantN: 2, wantOK: true},
		{name: "quota equal to the period is one CPU", content: "100000 100000", wantN: 1, wantOK: true},
		{name: "quota below the period floors at one CPU", content: "50000 100000", wantN: 1, wantOK: true},
		{name: "max quota means no ceiling", content: "max 100000\n"},
		{name: "zero quota is rejected", content: "0 100000"},
		{name: "negative quota is rejected", content: "-5 100000"},
		{name: "non-numeric quota is rejected", content: "abc 100000"},
		{name: "zero period is rejected", content: "100000 0"},
		{name: "negative period is rejected", content: "100000 -1"},
		{name: "non-numeric period is rejected", content: "100000 abc"},
		{name: "single field is rejected", content: "100000"},
		{name: "three fields are rejected", content: "100000 100000 1"},
		{name: "empty file is rejected", content: ""},
		{name: "missing file is rejected", missing: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			streamsCgroupFile(t, dir, cgroupV2CPUMaxName, tc.content, tc.missing)
			gotN, gotOK := readCgroupV2(dir, cgroupV2CPUMaxName)
			if gotN != tc.wantN || gotOK != tc.wantOK {
				t.Errorf("readCgroupV2(%q): got = (%d, %t), want = (%d, %t)", tc.content, gotN, gotOK, tc.wantN, tc.wantOK)
			}
		})
	}
}

func TestReadCgroupV1CPUQuota(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		quota         string
		period        string
		quotaMissing  bool
		periodMissing bool
		wantN         int
		wantOK        bool
	}{
		{name: "quota three times the period is three CPUs", quota: "300000\n", period: "100000\n", wantN: 3, wantOK: true},
		{name: "fractional quota rounds up", quota: "250000", period: "100000", wantN: 3, wantOK: true},
		{name: "quota below the period floors at one CPU", quota: "20000", period: "100000", wantN: 1, wantOK: true},
		{name: "quota of -1 means no ceiling", quota: "-1\n", period: "100000\n"},
		{name: "zero quota is rejected", quota: "0", period: "100000"},
		{name: "non-numeric quota is rejected", quota: "abc", period: "100000"},
		{name: "missing quota file is rejected", quotaMissing: true, period: "100000"},
		{name: "zero period is rejected", quota: "200000", period: "0"},
		{name: "negative period is rejected", quota: "200000", period: "-1"},
		{name: "missing period file is rejected", quota: "200000", periodMissing: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			streamsCgroupFile(t, dir, cgroupV1CPUQuotaName, tc.quota, tc.quotaMissing)
			streamsCgroupFile(t, dir, cgroupV1CPUPeriodName, tc.period, tc.periodMissing)
			gotN, gotOK := readCgroupV1(dir, cgroupV1CPUQuotaName, cgroupV1CPUPeriodName)
			if gotN != tc.wantN || gotOK != tc.wantOK {
				t.Errorf("readCgroupV1(%q, %q): got = (%d, %t), want = (%d, %t)", tc.quota, tc.period, gotN, gotOK, tc.wantN, tc.wantOK)
			}
		})
	}
}

func TestReadIntFile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		missing bool
		want    int64
		wantOK  bool
	}{
		{name: "integer with trailing newline", content: "12345\n", want: 12345, wantOK: true},
		{name: "negative integer with surrounding space", content: "  -1 \n", want: -1, wantOK: true},
		{name: "non-numeric content is rejected", content: "abc"},
		{name: "empty file is rejected", content: ""},
		{name: "missing file is rejected", missing: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			streamsCgroupFile(t, dir, "value", tc.content, tc.missing)
			got, gotOK := readIntFile(dir, "value")
			if got != tc.want || gotOK != tc.wantOK {
				t.Errorf("readIntFile(%q): got = (%d, %t), want = (%d, %t)", tc.content, got, gotOK, tc.want, tc.wantOK)
			}
		})
	}
}

// TestReadIntFileStaysInDir checks that a name, or a symlink, leading outside
// the directory is not read, even when the file it reaches holds an integer.
func TestReadIntFileStaysInDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		read string
	}{
		{name: "parent reference is refused", read: filepath.Join("..", "value")},
		{name: "symlink leading outside is refused", read: "link"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			streamsCgroupFile(t, base, "value", "12345", false)
			if err := file.MkdirAllIn(base, "cgroup", 0o700); err != nil {
				t.Fatalf("create cgroup: %v", err)
			}
			dir := filepath.Join(base, "cgroup")
			r, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("open cgroup: %v", err)
			}
			defer r.Close()
			if err := r.Symlink(filepath.Join("..", "value"), "link"); err != nil {
				t.Fatalf("symlink: %v", err)
			}

			got, gotOK := readIntFile(dir, tt.read)
			if got != 0 || gotOK {
				t.Errorf("readIntFile(%q): got = (%d, %t), want = (0, false)", tt.read, got, gotOK)
			}
		})
	}
}

func TestCeilDiv(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		a, b int64
		want int
	}{
		{name: "exact multiple", a: 200000, b: 100000, want: 2},
		{name: "remainder rounds up", a: 250000, b: 100000, want: 3},
		{name: "equal operands", a: 100000, b: 100000, want: 1},
		{name: "one over a multiple rounds up", a: 100001, b: 100000, want: 2},
		{name: "small numerator rounds up to one", a: 1, b: 100000, want: 1},
		{name: "zero numerator floors at one", a: 0, b: 100000, want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ceilDiv(tc.a, tc.b); got != tc.want {
				t.Errorf("ceilDiv(%d, %d): got = %d, want = %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
