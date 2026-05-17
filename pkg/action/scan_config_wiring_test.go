// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// buildPayloadZip writes a single-entry uncompressed zip at zipPath whose
// payload is `size` bytes of 'A'.
func buildPayloadZip(t *testing.T, zipPath string, size int) {
	t.Helper()

	zf, err := os.OpenFile(zipPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer func() { _ = zf.Close() }()

	zw := zip.NewWriter(zf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "payload.bin", Method: zip.Store})
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	if _, err := w.Write(bytes.Repeat([]byte{'A'}, size)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
}

func TestScan_WiresMaxArchiveBytesFromConfig(t *testing.T) {
	ctx := context.Background()

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	r, err := render.New("json", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "oversize.zip")
	const payload = 4096
	buildPayloadZip(t, zipPath, payload)

	mc := malcontent.Config{
		Concurrency:      runtime.NumCPU(),
		ExitExtraction:   true,
		IncludeDataFiles: true,
		MaxArchiveBytes:  64,
		MinFileRisk:      0,
		MinRisk:          0,
		Renderer:         r,
		Rules:            yrs,
		ScanPaths:        []string{zipPath},
	}

	_, scanErr := Scan(ctx, mc)
	if scanErr == nil {
		t.Fatalf("Scan returned nil; want chain containing ErrArchiveBytesCap")
	}
	if !errors.Is(scanErr, file.ErrArchiveBytesCap) {
		t.Fatalf("Scan err = %v; want chain containing ErrArchiveBytesCap", scanErr)
	}
	if !strings.Contains(scanErr.Error(), "zip extraction aborted") {
		t.Fatalf("Scan err = %v; want zip extraction abort message", scanErr)
	}
}
