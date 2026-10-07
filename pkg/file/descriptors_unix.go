// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package file

import (
	"math"

	"golang.org/x/sys/unix"
)

// openFileLimit returns how many files the process may have open.
func openFileLimit() int64 {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return 1024
	}
	if lim.Cur > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(lim.Cur)
}

// growDescriptorTable makes the process's descriptor table hold at least n
// descriptors, by duplicating a standard descriptor to the n-th and closing
// the copy.
func growDescriptorTable(n int64) {
	for fd := range 3 {
		if dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, int(n-1)); err == nil {
			_ = unix.Close(dup)
			return
		}
	}
}
