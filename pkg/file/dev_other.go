// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package file

import "io/fs"

// Inode reports no device or inode: other systems' FileInfo does not hold
// them.
func Inode(fs.FileInfo) (dev, ino uint64, ok bool) { return 0, 0, false }

// devOf reports no device, so walks find no filesystem boundaries.
func devOf(fs.FileInfo) (uint64, bool) { return 0, false }
