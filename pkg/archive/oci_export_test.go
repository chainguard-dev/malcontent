// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"go.uber.org/goleak"
)

const ociExportLimitErr = "export size exceeds maximum allowed size"

func TestOCIBudgetReader_EnforcesCumulativeLimits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		maxImageSize int64
		maxArchive   int64
		reads        []int
		failAt       int // index of the first rejected read, or -1
		wantErr      error
	}{
		{name: "reads that exactly fill the image limit succeed", maxImageSize: 8, reads: []int{3, 5}, failAt: -1},
		{name: "a read past the image limit is rejected", maxImageSize: 8, reads: []int{3, 5, 1}, failAt: 2, wantErr: errImageTooLarge},
		{name: "a single read over the image limit is rejected", maxImageSize: 8, reads: []int{9}, failAt: 0, wantErr: errImageTooLarge},
		{name: "a read past the archive cap is rejected", maxArchive: 8, reads: []int{4, 4, 4}, failAt: 2, wantErr: file.ErrArchiveBytesCap},
		{name: "a zero image limit is unlimited", reads: []int{1 << 20}, failAt: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var src bytes.Buffer
			for _, n := range tc.reads {
				src.Write(bytes.Repeat([]byte{'x'}, n))
			}
			budget := &ociBudget{maxImageSize: tc.maxImageSize, archive: &file.ArchiveCounter{MaxBytes: tc.maxArchive}}
			r := &ociBudgetReader{r: &src, budget: budget}
			for i, size := range tc.reads {
				n, err := r.Read(make([]byte, size))
				if n != size {
					t.Errorf("read %d count: got = %d, want = %d", i, n, size)
				}
				if i == tc.failAt {
					if !errors.Is(err, tc.wantErr) {
						t.Errorf("read %d error: got = %v, want wrapping %v", i, err, tc.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("read %d: %v", i, err)
				}
			}
		})
	}
}

// ociPaddedLayer returns a gzip layer holding hello.txt. Its tar stream is
// zero-padded to a full 10 KiB tar record and stored without compression, so
// the blob is larger than the flattened export and an image-size limit equal
// to the manifest total also admits the export.
func ociPaddedLayer(t *testing.T) []byte {
	t.Helper()
	record := make([]byte, 10<<10)
	copy(record, ociTar(t, ociFile{name: ociHelloName, body: []byte(ociHelloBody)}))
	return ociGzip(t, gzip.NoCompression, record)
}

func TestOCIWithConfig_ImageSizeLimitBoundaries(t *testing.T) {
	t.Parallel()
	layerBlob := ociPaddedLayer(t)
	var emptyBlob []byte
	layer := ociBlobDesc(types.DockerLayer, layerBlob)
	empty := ociBlobDesc(types.DockerLayer, emptyBlob)
	config := ociBlobDesc(types.DockerConfigJSON, ociConfigBlob)
	zeroConfig := config
	zeroConfig.size = 0
	// Four of these sum to 2^64, which wraps an unchecked int64 total to zero.
	wrapping := layer
	wrapping.size = 1 << 62
	total := layer.size + config.size

	cases := []struct {
		name          string
		config        ociDesc
		layers        []ociDesc
		limit         int64
		wantExtracted bool
	}{
		{
			name:          "zero limit disables the size checks",
			config:        config,
			layers:        []ociDesc{layer},
			limit:         0,
			wantExtracted: true,
		},
		{
			name:          "manifest total equal to the limit is accepted",
			config:        config,
			layers:        []ociDesc{layer},
			limit:         total,
			wantExtracted: true,
		},
		{
			name:   "manifest total one byte over the limit is rejected",
			config: config,
			layers: []ociDesc{layer},
			limit:  total - 1,
		},
		{
			name:          "zero-size config descriptor is accepted",
			config:        zeroConfig,
			layers:        []ociDesc{layer},
			limit:         layer.size,
			wantExtracted: true,
		},
		{
			name:          "zero-size layer descriptor is accepted",
			config:        config,
			layers:        []ociDesc{layer, empty},
			limit:         total,
			wantExtracted: true,
		},
		{
			name:   "running layer total over the limit is rejected",
			config: config,
			layers: []ociDesc{layer, layer, layer},
			limit:  2*layer.size + config.size,
		},
		{
			name:   "layer sizes that wrap the running total are rejected",
			config: config,
			layers: []ociDesc{wrapping, wrapping, wrapping, wrapping},
			limit:  1 << 16,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := newOCIImageRegistry(t, [][]byte{layerBlob, emptyBlob, ociConfigBlob}, tc.config, tc.layers...)
			_, ref := ociServe(t, reg)
			dir, err := OCIWithConfig(t.Context(), ref, ociTestConfig(tc.limit))
			if dir != "" {
				t.Cleanup(func() { _ = file.RemoveAllIn(filepath.Dir(dir), filepath.Base(dir)) })
			}
			if tc.wantExtracted {
				if err != nil {
					t.Fatalf("OCIWithConfig: %v", err)
				}
				ociAssertHelloExtracted(t, dir)
				return
			}
			want := fmt.Sprintf("image size exceeds maximum allowed size (%d bytes)", tc.limit)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error: got = %v, want containing %q", err, want)
			}
			if got := reg.blobHits.Load(); got != 0 {
				t.Errorf("blob requests before rejection: got = %d, want = 0", got)
			}
		})
	}
}

// TestOCIWithConfig_OversizedExportStopsWithoutLeaks covers an image whose
// manifest passes the size preflight while its flattened export does not:
// 1 MiB of zeros gzips to about a kilobyte. The export must stop at the limit
// and release the flattening goroutine and the layer stream it reads.
//
// Not parallel: the goroutine check compares against this test's starting
// snapshot.
func TestOCIWithConfig_OversizedExportStopsWithoutLeaks(t *testing.T) {
	ignore := goleak.IgnoreCurrent()
	// Registered first so it runs after the registry server has shut down.
	t.Cleanup(func() { goleak.VerifyNone(t, ignore) })

	layerBlob := ociGzip(t, gzip.BestCompression, ociTar(t, ociFile{name: "zeros.bin", body: make([]byte, 1<<20)}))
	reg := newOCIImageRegistry(t, [][]byte{layerBlob, ociConfigBlob},
		ociBlobDesc(types.DockerConfigJSON, ociConfigBlob), ociBlobDesc(types.DockerLayer, layerBlob))
	_, ref := ociServe(t, reg)

	dir, err := OCIWithConfig(t.Context(), ref, ociTestConfig(64<<10))
	if err == nil {
		_ = file.RemoveAllIn(filepath.Dir(dir), filepath.Base(dir))
		t.Fatalf("error: got = nil, want = %q", ociExportLimitErr)
	}
	if !strings.Contains(err.Error(), ociExportLimitErr) {
		t.Errorf("error: got = %v, want containing %q", err, ociExportLimitErr)
	}
	if reg.blobHits.Load() == 0 {
		t.Errorf("blob requests: got = 0, want > 0 (the manifest passes the preflight)")
	}
}

// TestOCIWithConfig_SingleArtifactBlobExportedVerbatim covers images whose only
// layer has a non-layer media type. The blob reaches tar extraction byte for
// byte instead of being re-flattened, so bytes hidden past its end-of-archive
// marker still reach the trailer audit.
func TestOCIWithConfig_SingleArtifactBlobExportedVerbatim(t *testing.T) {
	t.Parallel()
	const artifactType types.MediaType = "application/vnd.malcontent.test.archive"
	clean := ociTar(t, ociFile{name: ociHelloName, body: []byte(ociHelloBody)})
	cases := []struct {
		name      string
		blob      []byte
		wantErrIs error
	}{
		{name: "clean archive is extracted", blob: clean},
		{name: "bytes past the end-of-archive marker are reported", blob: append(slices.Clone(clean), "hidden payload"...), wantErrIs: ErrUnaccountedBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := newOCIImageRegistry(t, [][]byte{tc.blob, ociConfigBlob},
				ociBlobDesc(types.DockerConfigJSON, ociConfigBlob), ociBlobDesc(artifactType, tc.blob))
			_, ref := ociServe(t, reg)
			dir, err := OCIWithConfig(t.Context(), ref, ociTestConfig(0))
			if dir != "" {
				t.Cleanup(func() { _ = file.RemoveAllIn(filepath.Dir(dir), filepath.Base(dir)) })
			}
			if tc.wantErrIs == nil {
				if err != nil {
					t.Fatalf("OCIWithConfig: %v", err)
				}
				ociAssertHelloExtracted(t, dir)
				return
			}
			if !errors.Is(err, tc.wantErrIs) {
				t.Errorf("error: got = %v, want wrapping %v", err, tc.wantErrIs)
			}
		})
	}
}

// TestOCIWithConfig_ReferenceDoesNotShapeExtraction checks that names in the
// reference neither select a decompressor nor overflow a file name limit.
func TestOCIWithConfig_ReferenceDoesNotShapeExtraction(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		repo string
	}{
		{name: "an .apk repository is not read as gzip", repo: "tools.apk:1"},
		{name: "an .xz tag is not read as xz", repo: "tools:1.xz"},
		{name: "a .tbz repository is not read as bzip2", repo: "tools.tbz:1"},
		{name: "a .tar.gz repository is extracted", repo: "tools.tar.gz:1"},
		{name: "a long repository and tag fit the temp names", repo: strings.Repeat("a", 180) + ":" + strings.Repeat("b", 100)},
	}
	host := ociTestRegistry(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ref := host + "/refs/" + tc.repo
			ociPushImage(t, ref, ociTestImage(t, []ociTestEntry{{name: "ok.txt", body: "ok"}}))
			dir, err := OCIWithConfig(t.Context(), ref, ociTestConfig(0))
			removeOCIDir(t, dir)
			if err != nil {
				t.Fatalf("OCIWithConfig: %v", err)
			}
			if !strings.HasPrefix(filepath.Base(dir), "malcontent-oci-") {
				t.Errorf("extraction directory: got = %q, want a malcontent-oci-* name", filepath.Base(dir))
			}
			ociAssertTree(t, dir, map[string]string{"ok.txt": "file:ok"})
		})
	}
}

// TestOCIWithConfig_HiddenBytesCountAgainstLimits checks that the size limits
// count every byte decompressed from a layer, including content an upper layer
// deletes, which is never written out.
func TestOCIWithConfig_HiddenBytesCountAgainstLimits(t *testing.T) {
	t.Parallel()
	zeros := string(make([]byte, 1<<20))
	cases := []struct {
		name            string
		layers          [][]ociTestEntry
		maxImageSize    int64
		maxArchiveBytes int64
		wantErr         string
		wantErrIs       error
	}{
		{
			name:         "whited-out bytes count against the image size limit",
			layers:       [][]ociTestEntry{{{name: "zeros.bin", body: zeros}}, {{name: ".wh.zeros.bin"}}},
			maxImageSize: 64 << 10,
			wantErr:      ociExportLimitErr,
		},
		{
			name:            "whited-out bytes count against the archive byte cap",
			layers:          [][]ociTestEntry{{{name: "zeros.bin", body: zeros}}, {{name: ".wh.zeros.bin"}}},
			maxArchiveBytes: 64 << 10,
			wantErrIs:       file.ErrArchiveBytesCap,
		},
		{
			name:            "an image within both limits is extracted",
			layers:          [][]ociTestEntry{{{name: "ok.txt", body: "ok"}}},
			maxImageSize:    64 << 10,
			maxArchiveBytes: 64 << 10,
		},
	}
	host := ociTestRegistry(t)
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ref := fmt.Sprintf("%s/hidden:case%d", host, i)
			ociPushImage(t, ref, ociTestImage(t, tc.layers...))
			c := ociTestConfig(tc.maxImageSize)
			c.MaxArchiveBytes = tc.maxArchiveBytes
			dir, err := OCIWithConfig(t.Context(), ref, c)
			removeOCIDir(t, dir)
			switch {
			case tc.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error: got = %v, want containing %q", err, tc.wantErr)
				}
			case tc.wantErrIs != nil:
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("error: got = %v, want wrapping %v", err, tc.wantErrIs)
				}
			case err != nil:
				t.Fatalf("OCIWithConfig: %v", err)
			default:
				ociAssertTree(t, dir, map[string]string{"ok.txt": "file:ok"})
			}
		})
	}
}

// removeOCIDir removes dir, a directory OCIWithConfig returned, when the test
// ends.
func removeOCIDir(t *testing.T, dir string) {
	t.Helper()
	if dir != "" {
		t.Cleanup(func() { _ = file.RemoveAllIn(filepath.Dir(dir), filepath.Base(dir)) })
	}
}
