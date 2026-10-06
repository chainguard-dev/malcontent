// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package file

import "os"

// mapFile maps nothing on this platform, so ReadContents reads every file.
func mapFile(*os.File) ([]byte, error) {
	return nil, errNotMappable
}

// unmapFile is never reached here, because mapFile maps nothing.
func unmapFile([]byte) error {
	return nil
}
