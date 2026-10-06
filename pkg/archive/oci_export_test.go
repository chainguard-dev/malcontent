// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/types"
	"go.uber.org/goleak"
)

const ociExportLimitErr = "export size exceeds maximum allowed size"

func TestLimitedWriter_EnforcesCumulativeLimit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		limit     int64
		writes    []int
		failAt    int // index of the first rejected write, or -1
		wantBytes int
	}{
		{name: "writes that exactly fill the limit succeed", limit: 8, writes: []int{3, 5}, failAt: -1, wantBytes: 8},
		{name: "a write past the remaining budget is rejected", limit: 8, writes: []int{3, 5, 1}, failAt: 2, wantBytes: 8},
		{name: "a single write over the limit is rejected", limit: 8, writes: []int{9}, failAt: 0, wantBytes: 0},
		{name: "repeated writes draw on one budget", limit: 8, writes: []int{4, 4, 4}, failAt: 2, wantBytes: 8},
		{name: "an empty write fits an exhausted budget", limit: 0, writes: []int{0}, failAt: -1, wantBytes: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			lw := &limitedWriter{w: &out, remaining: tc.limit}
			for i, size := range tc.writes {
				n, err := lw.Write(bytes.Repeat([]byte{'x'}, size))
				if i == tc.failAt {
					if err == nil || !strings.Contains(err.Error(), ociExportLimitErr) {
						t.Errorf("write %d error: got = %v, want = %q", i, err, ociExportLimitErr)
					}
					if n != 0 {
						t.Errorf("write %d count: got = %d, want = 0", i, n)
					}
					break
				}
				if err != nil {
					t.Fatalf("write %d: %v", i, err)
				}
				if n != size {
					t.Errorf("write %d count: got = %d, want = %d", i, n, size)
				}
			}
			if out.Len() != tc.wantBytes {
				t.Errorf("bytes passed through: got = %d, want = %d", out.Len(), tc.wantBytes)
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
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
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
		_ = os.RemoveAll(dir)
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
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
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
