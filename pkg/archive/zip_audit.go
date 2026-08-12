// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// zipEOCDLen is the fixed size of the end-of-central-directory record.
	zipEOCDLen = 22
	// zipMaxCommentLen is the largest archive comment the format can express.
	zipMaxCommentLen = 65535
	// zip64Sentinel marks a field whose real value lives in the zip64 record.
	zip64Sentinel = 0xFFFFFFFF
)

var (
	zipEOCDSignature      = []byte("PK\x05\x06")
	zip64LocatorSignature = []byte("PK\x06\x07")
)

// zipUnaccountedBytes reports regions of a zip archive that no entry describes.
//
// Zip readers locate the central directory from the end of the file, so bytes
// appended after the end-of-central-directory record are ignored entirely: they
// are neither extracted nor reported, and the archive is deleted as fully
// processed. The same holds for bytes wedged between the central directory and
// its end record.
//
// Gaps between individual entry payloads are not covered, because entry offsets
// are not exposed by the zip reader API.
func zipUnaccountedBytes(path string, size int64) error {
	if size < zipEOCDLen {
		return nil
	}

	tailLen := min(int64(zipEOCDLen+zipMaxCommentLen), size)

	fh, err := os.Open(path) // #nosec G304 -- archive path resolved and validated by caller before extraction
	if err != nil {
		// The extractor already read this file, so auditing is best-effort.
		return nil
	}
	defer fh.Close()

	tail := make([]byte, tailLen)
	if _, err := fh.ReadAt(tail, size-tailLen); err != nil && !errors.Is(err, io.EOF) {
		// An unreadable tail cannot be audited either way.
		return nil
	}

	idx := findZipEOCD(tail)
	if idx < 0 {
		// Not locatable, so the reader would not have opened the archive.
		return nil
	}

	eocdOffset := size - tailLen + int64(idx)
	commentLen := int64(binary.LittleEndian.Uint16(tail[idx+20:]))
	if recordEnd := eocdOffset + zipEOCDLen + commentLen; recordEnd != size {
		return fmt.Errorf("%d bytes follow the end-of-central-directory record", size-recordEnd)
	}

	cdSize := int64(binary.LittleEndian.Uint32(tail[idx+12:]))
	cdOffset := int64(binary.LittleEndian.Uint32(tail[idx+16:]))

	// zip64 keeps the real offsets in records this walk does not parse.
	if cdSize == zip64Sentinel || cdOffset == zip64Sentinel {
		return nil
	}
	if idx >= 20 && bytes.Equal(tail[idx-20:idx-16], zip64LocatorSignature) {
		return nil
	}

	if cdOffset+cdSize != eocdOffset {
		return errors.New("central directory does not end where its end record begins")
	}

	return nil
}

// findZipEOCD locates the end-of-central-directory record the way zip readers
// do: the last signature whose declared comment length fits in the tail.
func findZipEOCD(tail []byte) int {
	for i := len(tail) - zipEOCDLen; i >= 0; i-- {
		if !bytes.Equal(tail[i:i+4], zipEOCDSignature) {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(tail[i+20:]))
		if i+zipEOCDLen+commentLen <= len(tail) {
			return i
		}
	}
	return -1
}
