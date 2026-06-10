// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/chainguard-dev/malcontent/pkg/file"
)

// makeCPIOStream returns a CPIO reader positioned at the first member, which
// carries body under name.
func makeCPIOStream(t *testing.T, name string, body []byte) *cpio.Reader {
	t.Helper()
	var buf bytes.Buffer
	cw := cpio.NewWriter(&buf)
	hdr := &cpio.Header{Name: name, Mode: 0o600 | cpio.TypeReg, Size: int64(len(body))}
	if err := cw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := cw.Write(body); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	cr := cpio.NewReader(&buf)
	if _, err := cr.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	return cr
}

// TestExtractFileFromCPIO_AggregateCap proves the CPIO extractor honors the
// shared counter so the aggregate byte cap fires when a member would push the
// running total past MaxBytes. A nil-safe counter seeded by ExtractRPM is what
// makes the cap span all members; here a single oversize member trips it.
func TestExtractFileFromCPIO_AggregateCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	body := make([]byte, 4096)
	cr := makeCPIOStream(t, "payload.bin", body)
	target := filepath.Join(dir, "payload.bin")

	buf := make([]byte, file.ExtractBuffer)
	counter := &file.ArchiveCounter{MaxBytes: 1024, InputBytes: 1 << 20}

	err := extractFileFromCPIO(context.Background(), cr, target, buf, counter)
	if err == nil {
		t.Fatalf("extractFileFromCPIO succeeded; want ErrArchiveBytesCap")
	}
	if !errors.Is(err, file.ErrArchiveBytesCap) {
		t.Fatalf("err = %v; want chain containing ErrArchiveBytesCap", err)
	}
}

// makeTarMember returns a tar reader positioned at a single regular-file member
// carrying body at name.
func makeTarMember(t *testing.T, name string, body []byte) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tr := tar.NewReader(&buf)
	if _, err := tr.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	return tr
}

// TestHandleFile_AggregateCap proves the tar-member writer ExtractDeb relies on
// enforces the aggregate byte cap through the shared counter rather than
// opting out with a nil counter. Two members accumulate against one counter and
// the second trips the cap.
func TestHandleFile_AggregateCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	counter := &file.ArchiveCounter{MaxBytes: 1500, InputBytes: 1 << 20}

	first := makeTarMember(t, "a.bin", make([]byte, 1024))
	if err := handleFile(filepath.Join(dir, "a.bin"), first, counter); err != nil {
		t.Fatalf("first member: unexpected error %v", err)
	}

	second := makeTarMember(t, "b.bin", make([]byte, 1024))
	err := handleFile(filepath.Join(dir, "b.bin"), second, counter)
	if err == nil {
		t.Fatalf("second member succeeded; want ErrArchiveBytesCap")
	}
	if !errors.Is(err, file.ErrArchiveBytesCap) {
		t.Fatalf("err = %v; want chain containing ErrArchiveBytesCap", err)
	}
}
