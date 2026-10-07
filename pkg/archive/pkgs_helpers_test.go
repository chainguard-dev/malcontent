// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// Compression names as an RPM header spells them.
const (
	pkgsGzip = "gzip"
	pkgsXZ   = "xz"
	pkgsZstd = "zstd"
)

// pkgsCompress compresses payload with the named compression.
func pkgsCompress(t *testing.T, compression string, payload []byte) []byte {
	t.Helper()
	switch compression {
	case pkgsGzip:
		return gzipBytes(t, payload)
	case pkgsXZ:
		var buf bytes.Buffer
		w, err := xz.NewWriter(&buf)
		if err != nil {
			t.Fatalf("xz writer: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("xz write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("xz close: %v", err)
		}
		return buf.Bytes()
	case pkgsZstd:
		enc, err := zstd.NewWriter(nil)
		if err != nil {
			t.Fatalf("zstd writer: %v", err)
		}
		defer enc.Close()
		return enc.EncodeAll(payload, nil)
	default:
		t.Fatalf("no encoder for compression %q", compression)
		return nil
	}
}

// pkgsCountdownContext reports no error from its first allow calls to Err and
// context.Canceled from every later call, so a test chooses which of an
// extractor's cancellation checks observes the cancellation.
type pkgsCountdownContext struct {
	context.Context
	allow int64
	calls atomic.Int64
}

func (c *pkgsCountdownContext) Err() error {
	if c.calls.Add(1) > c.allow {
		return context.Canceled
	}
	return nil
}

// pkgsNoise returns n deterministic bytes that do not compress, so that
// compressed fixtures stay under the expansion ratio cap.
func pkgsNoise(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.NewChaCha8([32]byte{}).Read(b)
	return b
}

// pkgsWantFile fails unless path holds exactly want.
func pkgsWantFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := file.ReadFileIn(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		t.Errorf("read %s: %v", path, err)
		return
	}
	if string(got) != want {
		t.Errorf("%s: got = %q, want = %q", path, got, want)
	}
}

// pkgsWantAbsent fails if anything exists at path.
func pkgsWantAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := file.LstatIn(filepath.Dir(path), filepath.Base(path)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("lstat %s: got = %v, want = %v", path, err, fs.ErrNotExist)
	}
}

// pkgsWantSymlink fails unless path is a symlink whose target is want.
func pkgsWantSymlink(t *testing.T, path, want string) {
	t.Helper()
	r, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Errorf("readlink %s: %v", path, err)
		return
	}
	defer r.Close()
	got, err := r.Readlink(filepath.Base(path))
	if err != nil {
		t.Errorf("readlink %s: %v", path, err)
		return
	}
	if got != want {
		t.Errorf("%s target: got = %q, want = %q", path, got, want)
	}
}

// pkgsWantSameFile fails unless a and b are hard links to one file.
func pkgsWantSameFile(t *testing.T, a, b string) {
	t.Helper()
	fa, err := file.StatIn(filepath.Dir(a), filepath.Base(a))
	if err != nil {
		t.Errorf("stat %s: %v", a, err)
		return
	}
	fb, err := file.StatIn(filepath.Dir(b), filepath.Base(b))
	if err != nil {
		t.Errorf("stat %s: %v", b, err)
		return
	}
	if !os.SameFile(fa, fb) {
		t.Errorf("%s and %s: got = separate files, want = one file", a, b)
	}
}
