// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package file

import (
	"io/fs"
	"syscall"
)

// Inode returns the device and inode number of the file fi describes, which
// two names of one file share, and whether fi reports them.
func Inode(fi fs.FileInfo) (dev, ino uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return widen(st.Dev), widen(st.Ino), true
}

// widen returns n as a uint64. Device and inode numbers vary in type and
// width by platform; they are only compared.
func widen[T ~int32 | ~uint32 | ~int64 | ~uint64](n T) uint64 { return uint64(n) }

// devOf returns the device holding the file fi describes, and whether fi
// reports it.
func devOf(fi fs.FileInfo) (uint64, bool) {
	dev, _, ok := Inode(fi)
	return dev, ok
}
