// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !linux

package file

import "golang.org/x/sys/unix"

// mmapFlags maps files shared. MAP_POPULATE is Linux-only.
const mmapFlags = unix.MAP_SHARED
