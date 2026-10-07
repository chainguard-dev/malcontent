// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"os"
	"testing"
)

const maxFuzzSize = 10 * 1024 * 1024

// fuzzFile writes data to a new file and returns it open for reading. It skips
// the input when the file cannot be created.
func fuzzFile(t *testing.T, data []byte) *os.File {
	t.Helper()
	dir := t.TempDir()
	if err := WriteFileIn(dir, "f", data, 0o600); err != nil {
		t.Skip()
	}
	f, err := OpenIn(dir, "f")
	if err != nil {
		t.Skip()
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func FuzzGetContents(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("hello"))
	f.Add(make([]byte, 4<<10))
	f.Add(make([]byte, ExtractBuffer))
	f.Add(make([]byte, 128<<10))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}
		contents, err := GetContents(fuzzFile(t, data))
		if err != nil {
			t.Fatalf("GetContents() error: got = %v, want = nil", err)
		}
		if !bytes.Equal(contents, data) {
			t.Errorf("GetContents(): got = %d bytes, want = the %d bytes written", len(contents), len(data))
		}
	})
}

// FuzzReadContents checks that the read and map paths return the bytes on
// disk whatever size they are told, as when a file grows or shrinks after it
// is stat'd. mapAbove stands in for mapThreshold so both paths see small
// inputs.
func FuzzReadContents(f *testing.F) {
	f.Add([]byte("hello"), int64(5), int64(4096))
	f.Add([]byte("hello"), int64(5), int64(1))
	f.Add([]byte("hello"), int64(1), int64(4096))
	f.Add([]byte("hello"), int64(4096), int64(4096))
	f.Add([]byte("hello"), int64(4097), int64(4096))
	f.Add(make([]byte, 4096), int64(4096), int64(4095))
	f.Add(make([]byte, 4097), int64(4096), int64(4096))
	f.Add(make([]byte, 4097), int64(4096), int64(1024))
	f.Add([]byte{}, int64(8192), int64(4096))

	f.Fuzz(func(t *testing.T, data []byte, size, mapAbove int64) {
		// The read path allocates for the size it is told, so keep that
		// within reason too.
		if len(data) > maxFuzzSize || size < 1 || size > 2*maxFuzzSize || mapAbove < 0 {
			return
		}
		c, err := loadContents(fuzzFile(t, data), size, mapAbove)
		if err != nil {
			t.Fatalf("loadContents(%d, %d) error: got = %v, want = nil", size, mapAbove, err)
		}
		defer c.Close()
		if got := c.Bytes(); !bytes.Equal(got, data) {
			t.Errorf("loadContents(%d, %d): got = %d bytes, want = the %d bytes written", size, mapAbove, len(got), len(data))
		}
	})
}
