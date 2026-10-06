// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package file

import (
	"math"
	"os"

	"golang.org/x/sys/unix"
)

// mapFile maps all of f read-only. It maps the file's length now rather than
// an earlier stat size, because touching a mapped page wholly past the end of
// a file that has since shrunk faults. The mapping stays valid after f
// closes.
func mapFile(f *os.File) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if !fi.Mode().IsRegular() || size <= 0 || size > math.MaxInt {
		return nil, errNotMappable
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		data   []byte
		mapErr error
	)
	err = rc.Control(func(fd uintptr) {
		data, mapErr = unix.Mmap(int(fd), 0, int(size), unix.PROT_READ, mmapFlags)
	})
	if err != nil {
		return nil, err
	}
	return data, mapErr
}

// unmapFile releases a mapping made by mapFile.
func unmapFile(data []byte) error {
	return unix.Munmap(data)
}
