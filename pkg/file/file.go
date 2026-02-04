// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"io"
	"os"
)

// common values used across malcontent for extracting and reading files.
const (
	DefaultPoolBuffer int64 = 4 * 1024   // 4KB
	ExtractBuffer     int64 = 64 * 1024  // 64KB
	MaxPoolBuffer     int64 = 128 * 1024 // 128KB
	MaxBytes          int64 = 1 << 32    // 4096MB
	ReadBuffer        int64 = 64 * 1024  // 64KB
	ZipBuffer         int64 = 2 * 1024   // 2KB
)

// GetContents takes a file, reads its contents, and returns them as a slice of bytes.
func GetContents(f *os.File, buf []byte) ([]byte, error) {
	b := &bytes.Buffer{}
	_, err := io.CopyBuffer(b, io.LimitReader(f, MaxBytes), buf)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
