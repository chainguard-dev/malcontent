// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package file

import "os"

// isPseudoFS reports no pseudo filesystems: other systems mount none that a
// walk of stored files reaches.
func isPseudoFS(*os.Root) bool { return false }
