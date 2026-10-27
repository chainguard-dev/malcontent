// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

// ErrUnsupportedArchive reports a file whose content and name show no format
// the archive extractor handles. Such a file is no archive to extract, and is
// scanned as it is.
var ErrUnsupportedArchive = errors.New("unsupported archive type")

// archiveKind is the format of an archive as its content shows it.
type archiveKind int

const (
	kindUnknown archiveKind = iota
	kindZip
	kindTar
	kindGzip
	kindXZ
	kindBzip2
	kindZstd
	kindZlib
	kindUPX
	kindRPM
	kindDeb
)

var (
	gzipMagic     = []byte{0x1f, 0x8b, 0x08}
	zstdMagic     = []byte{0x28, 0xb5, 0x2f, 0xfd}
	rpmMagic      = []byte{0xed, 0xab, 0xee, 0xdb}
	debMagic      = []byte("!<arch>\ndebian-binary")
	zipLocalMagic = []byte("PK\x03\x04")
)

// sniffKind returns the format of the archive in r, of size bytes, from its
// leading magic bytes, a tar header at its start, or a zip end record near
// its end, which also finds a zip with a script or other data prepended.
func sniffKind(r io.ReaderAt, size int64) archiveKind {
	head := make([]byte, min(size, tarBlockSize))
	n, _ := r.ReadAt(head, 0)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, gzipMagic):
		return kindGzip
	case bytes.HasPrefix(head, zipLocalMagic), bytes.HasPrefix(head, []byte("PK\x05\x06")), bytes.HasPrefix(head, []byte("PK\x07\x08")):
		return kindZip
	case bytes.HasPrefix(head, xzMagic):
		return kindXZ
	case len(head) >= 4 && bytes.HasPrefix(head, []byte("BZh")) && head[3] >= '1' && head[3] <= '9':
		return kindBzip2
	case bytes.HasPrefix(head, zstdMagic), len(head) >= 4 && head[0]&0xf0 == 0x50 && bytes.Equal(head[1:4], []byte{0x2a, 0x4d, 0x18}):
		return kindZstd
	case bytes.HasPrefix(head, rpmMagic):
		return kindRPM
	case bytes.HasPrefix(head, debMagic):
		return kindDeb
	case len(head) == tarBlockSize && (bytes.HasPrefix(head[257:], []byte("ustar")) || validTarHeader(head)):
		return kindTar
	}
	if _, err := readZipLayout(r, size); err == nil {
		return kindZip
	}
	return kindUnknown
}

// kindOfFileType returns the format programkind detected by content: the
// kinds it recognizes that magic bytes alone do not, UPX and zlib.
func kindOfFileType(ft *programkind.FileType) archiveKind {
	switch {
	case ft == nil:
		return kindUnknown
	case ft.MIME == "application/x-upx":
		return kindUPX
	case ft.MIME == "application/zlib":
		return kindZlib
	}
	return kindUnknown
}

// tarNames are the extensions of names that hold a tar, compressed or not.
// Content decides how such a file is decompressed; the name decides that what
// is decompressed is read as a tar rather than written out as one file.
var tarNames = map[string]struct{}{
	".apk":     {},
	".gem":     {},
	".tar":     {},
	".tar.bz2": {},
	".tar.gz":  {},
	".tar.xz":  {},
	".tbz":     {},
	".tgz":     {},
}

// extractorForKind returns how to extract a file named with extension ext
// whose content is of the given kind. Content decides the format; the
// extension only breaks the tie between reading a compressed stream as a tar
// and writing it out as a file. A file whose content shows no known format is
// extracted as its extension says, or not at all.
func extractorForKind(kind archiveKind, ext string) func(context.Context, string, string) error {
	_, tarName := tarNames[ext]
	switch kind {
	case kindZip:
		return ExtractZip
	case kindTar:
		return ExtractTar
	case kindGzip:
		if tarName {
			return ExtractTar
		}
		return ExtractGzip
	case kindXZ:
		// ExtractTar writes a file named .xz out as one file.
		return ExtractTar
	case kindBzip2:
		if tarName {
			return ExtractTar
		}
		return ExtractBz2
	case kindZstd:
		if tarName {
			return ExtractTar
		}
		return ExtractZstd
	case kindZlib:
		return ExtractZlib
	case kindUPX:
		return ExtractUPX
	case kindRPM:
		return ExtractRPM
	case kindDeb:
		return ExtractDeb
	case kindUnknown:
	}
	return ExtractionMethod(ext)
}

// extractDetected extracts the archive f into d, choosing the extractor from
// its content, as sniffKind sees it, and from ft, the kind programkind
// detected, for the formats only programkind recognizes.
func extractDetected(ctx context.Context, d, f string, ft *programkind.FileType) error {
	extract, err := chooseExtractor(f, ft)
	if err != nil {
		return err
	}
	return extract(ctx, d, f)
}

// chooseExtractor returns the extractor for the archive at path.
func chooseExtractor(path string, ft *programkind.FileType) (func(context.Context, string, string) error, error) {
	kind := kindOfFileType(ft)
	if kind == kindUnknown {
		in, fi, err := openRegular(path)
		if err != nil {
			return nil, err
		}
		kind = sniffKind(in, fi.Size())
		_ = in.Close()
	}
	extract := extractorForKind(kind, programkind.GetExt(path))
	if extract == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedArchive, path)
	}
	return extract, nil
}
