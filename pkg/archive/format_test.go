// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	zip "github.com/klauspost/compress/zip"
)

// nestIn returns a tar holding data under name.
func nestIn(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(data)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractArchiveToTempDirExtractsArchivesByContent(t *testing.T) {
	t.Parallel()
	// Deflated, the marker appears in no archive's raw bytes, so it is found
	// only once the archive holding it is extracted.
	body := strings.Repeat(benignMarker, 8)
	payload := zipSpecBytes(t, zip.Deflate, []zipSpecEntry{{name: "run.js", body: body}})
	tarData := tarSpecBytes(t, []tarSpec{{name: "run.js", body: body}}, true)
	tests := []struct {
		name string
		file string
		data []byte
	}{
		{name: "zip under a data name", file: "payload.dat", data: payload},
		{name: "zip as a VS Code extension", file: "ext.vsix", data: payload},
		{name: "zip as a NuGet package", file: "pkg.nupkg", data: payload},
		{name: "zip as a Python egg", file: "lib.egg", data: payload},
		{name: "zip as a browser extension", file: "addon.xpi", data: payload},
		{name: "gzip-compressed tar under a crate name", file: "lib.crate", data: gzipBytes(t, tarData)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "outer.tar", nestIn(t, tt.file, tt.data))
			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
			if err != nil {
				t.Fatalf("ExtractArchiveToTempDir: %v", err)
			}
			defer cleanupTempDir(t.Context(), dir)
			// The archive's entry, not the archive, holds exactly body.
			if !slices.Contains(slices.Collect(maps.Values(treeContents(t, dir))), body) {
				t.Errorf("nested %s was not extracted", tt.file)
			}
		})
	}
}

func TestOpenTreeKeepsWhatItCannotExtract(t *testing.T) {
	t.Parallel()
	script := "#!/bin/sh\nexec java -jar \"$0\" \"$@\"\n"
	jar := zipPrefixed(t, script, true)
	tests := []struct {
		name     string
		file     string
		data     []byte
		retained bool
		marker   string
	}{
		{name: "launcher script before a jar keeps the jar and its classes", file: "app.jar", data: jar, retained: true, marker: benignMarker},
		{name: "file named as a tar that holds none stays as it is", file: "evil.tar", data: []byte("#!/bin/sh\n# " + benignMarker + "\n"), retained: true, marker: benignMarker},
		{name: "tar holding only a directory stays as it is", file: "dirs.tar", data: tarSpecBytes(t, []tarSpec{{name: "d/", typeflag: tar.TypeDir}}, true), retained: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, tt.file, tt.data)
			tree, err := OpenTree(t.Context(), malcontent.Config{}, src)
			if err != nil {
				t.Fatalf("OpenTree: %v", err)
			}
			defer tree.Close()
			if _, err := os.Lstat(filepath.Join(tree.Dir(), tt.file)); (err == nil) != tt.retained {
				t.Errorf("archive retained: got = %v, want = %v", err == nil, tt.retained)
			}
			if tt.marker != "" && !corpusContains(t, tree.Dir(), tt.marker) {
				t.Errorf("marker absent from the tree")
			}
		})
	}
}

func TestNestedArchiveYieldingNoFilesStays(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		file  string
		data  []byte
		stays bool
	}{
		{name: "tar holding only a directory", file: "dirs.tar", data: tarSpecBytes(t, []tarSpec{{name: "d/", typeflag: tar.TypeDir}}, true), stays: true},
		{name: "tar holding a file", file: "files.tar", data: tarSpecBytes(t, []tarSpec{{name: "f", body: "f"}}, true)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "outer.tar", nestIn(t, tt.file, tt.data))
			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
			if err != nil {
				t.Fatalf("ExtractArchiveToTempDir: %v", err)
			}
			defer cleanupTempDir(t.Context(), dir)
			if _, err := os.Lstat(filepath.Join(dir, tt.file)); (err == nil) != tt.stays {
				t.Errorf("%s in the tree: got = %v, want = %v", tt.file, err == nil, tt.stays)
			}
		})
	}
}

func TestOpenTreeReportsWhatIsNoArchive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		file    string
		data    []byte
		wantErr error
	}{
		{name: "UPX name without UPX content", file: "x.upx", data: []byte("hello"), wantErr: ErrUnsupportedArchive},
		{name: "zlib name without zlib content", file: "x.zlib", data: []byte("hello"), wantErr: ErrUnsupportedArchive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, tt.file, tt.data)
			tree, err := OpenTree(t.Context(), malcontent.Config{}, src)
			if err == nil {
				_ = tree.Close()
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("OpenTree error: got = %v, want = %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractorsRefuseNonRegularFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fifo := filepath.Join(dir, "x.tar.gz")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	extractors := map[string]func(context.Context, string, string) error{
		"OpenTree": func(ctx context.Context, _, f string) error {
			tree, err := OpenTree(ctx, malcontent.Config{}, f)
			if err == nil {
				_ = tree.Close()
			}
			return err
		},
		"ExtractTar":  ExtractTar,
		"ExtractZip":  ExtractZip,
		"ExtractGzip": ExtractGzip,
		"ExtractBz2":  ExtractBz2,
		"ExtractZstd": ExtractZstd,
		"ExtractZlib": ExtractZlib,
		"ExtractRPM":  ExtractRPM,
		"ExtractDeb":  ExtractDeb,
	}
	for name, extract := range extractors {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			done := make(chan error, 1)
			go func() { done <- extract(t.Context(), filepath.Join(t.TempDir(), "out"), fifo) }()
			select {
			case err := <-done:
				if !errors.Is(err, errNotRegular) {
					t.Errorf("%s error: got = %v, want = %v", name, err, errNotRegular)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s blocked on a FIFO", name)
			}
		})
	}
}

func TestNestedArchivesShareTheByteCap(t *testing.T) {
	t.Parallel()
	inner := zipSpecBytes(t, zip.Deflate, []zipSpecEntry{
		{name: "zeros.bin", body: string(make([]byte, 500<<10))},
		{name: "noise.bin", body: string(pkgsNoise(8 << 10))},
	})
	mids := make([]zipSpecEntry, 0, 10)
	for i := range 10 {
		mids = append(mids, zipSpecEntry{name: fmt.Sprintf("inner%02d.zip", i), body: string(inner)})
	}
	mid := zipSpecBytes(t, zip.Deflate, mids)
	var outer bytes.Buffer
	tw := tar.NewWriter(&outer)
	for i := range 10 {
		_ = tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("mid%02d.zip", i), Mode: 0o644, Size: int64(len(mid))})
		_, _ = tw.Write(mid)
	}
	_ = tw.Close()
	src := writeTemp(t, "outer.tar", outer.Bytes())

	const maxBytes = 4 << 20
	cfg := malcontent.Config{MaxArchiveBytes: maxBytes}
	dir, err := ExtractArchiveToTempDir(malcontent.ContextWithConfig(t.Context(), &cfg), cfg, src)
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir: %v", err)
	}
	defer cleanupTempDir(t.Context(), dir)
	// Archives the cap stopped stay in the tree as they are, so the tree
	// holds the cap's worth of extracted content plus those archives.
	_, size := treeSize(t, dir)
	if limit := int64(maxBytes) + int64(outer.Len()); size > limit {
		t.Errorf("tree holds %d bytes, want at most %d for a %d byte cap", size, limit, maxBytes)
	}
}

func TestEntryCostBoundsEmptyEntries(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range 1000 {
		_ = tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("d/f%04d", i), Mode: 0o644})
	}
	_ = tw.Close()
	src := writeTemp(t, "many.tar.gz", gzipBytes(t, buf.Bytes()))
	tests := []struct {
		name     string
		maxBytes int64
		wantErr  bool
	}{
		{name: "cap below the entries' fixed cost stops extraction", maxBytes: 100 * entryCost, wantErr: true},
		{name: "cap above the entries' fixed cost extracts them all", maxBytes: 2000 * entryCost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := malcontent.Config{MaxArchiveBytes: tt.maxBytes}
			err := ExtractTar(malcontent.ContextWithConfig(t.Context(), &cfg), filepath.Join(t.TempDir(), "out"), src)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractTar error: got = %v, want error = %v", err, tt.wantErr)
			}
		})
	}
}

// treeSize returns how many regular files dir holds and their total size.
func treeSize(t *testing.T, dir string) (int, int64) {
	t.Helper()
	files, size := 0, int64(0)
	for _, content := range treeContents(t, dir) {
		if content != "/" {
			files++
			size += int64(len(content))
		}
	}
	return files, size
}
