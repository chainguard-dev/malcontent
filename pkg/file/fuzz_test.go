// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"os"
	"testing"
)

const maxFuzzSize = 10 * 1024 * 1024

func FuzzGetContents(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("hello"))
	f.Add(make([]byte, 4096))   // DefaultPoolBuffer
	f.Add(make([]byte, 65536))  // ExtractBuffer/ReadBuffer
	f.Add(make([]byte, 131072)) // MaxPoolBuffer boundary

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}

		tmpFile, err := os.CreateTemp("", "fuzz-contents-*")
		if err != nil {
			t.Skip()
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip()
		}
		// Seek back to beginning for reading
		if _, err := tmpFile.Seek(0, 0); err != nil {
			t.Skip()
		}

		buf := make([]byte, ExtractBuffer)
		contents, err := GetContents(tmpFile, buf)
		tmpFile.Close()

		if err != nil {
			return
		}

		// Contents should match what we wrote (up to MaxBytes)
		if int64(len(data)) <= MaxBytes {
			if len(contents) != len(data) {
				t.Errorf("contents length %d != data length %d", len(contents), len(data))
			}
		}
	})
}
