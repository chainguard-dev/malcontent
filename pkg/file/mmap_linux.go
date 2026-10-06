// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import "golang.org/x/sys/unix"

// mmapFlags maps files shared and prefaults every page up front: detection,
// hashing, and scanning read the whole file, and one populate pass costs less
// than a page fault per page.
const mmapFlags = unix.MAP_SHARED | unix.MAP_POPULATE
