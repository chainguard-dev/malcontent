// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"compress/gzip"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// TestOCIWithConfig_TempStateReleased checks that every way an image pull can
// end leaves nothing behind in the temp directory except the extraction
// directory of a successful pull, and no open descriptor to the exported
// tarball.
//
// Not parallel: points TMPDIR at a per-case directory.
func TestOCIWithConfig_TempStateReleased(t *testing.T) {
	config := ociBlobDesc(types.DockerConfigJSON, ociConfigBlob)
	cases := []struct {
		name    string
		setup   func(t *testing.T) (string, *malcontent.Config)
		wantErr string // empty for a successful pull
	}{
		{
			name: "successful pull keeps only the extraction directory",
			setup: func(t *testing.T) (string, *malcontent.Config) {
				t.Helper()
				layer := ociGzip(t, gzip.DefaultCompression, ociTar(t, ociFile{name: ociHelloName, body: []byte(ociHelloBody)}))
				_, ref := ociServe(t, newOCIImageRegistry(t, [][]byte{layer, ociConfigBlob}, config, ociBlobDesc(types.DockerLayer, layer)))
				return ref, ociTestConfig(0)
			},
		},
		{
			name: "invalid CA bundle path removes the temp directory",
			setup: func(t *testing.T) (string, *malcontent.Config) {
				t.Helper()
				c := ociTestConfig(0)
				c.OCICABundlePath = "relative-ca.pem"
				return "127.0.0.1:1/fixture:latest", c
			},
			wantErr: "build OCI transport",
		},
		{
			name: "failed manifest fetch removes the temp directory",
			setup: func(t *testing.T) (string, *malcontent.Config) {
				t.Helper()
				_, ref := ociServe(t, &ociFixtureRegistry{manifestStatus: http.StatusNotFound})
				return ref, ociTestConfig(0)
			},
			wantErr: "failed to pull image",
		},
		{
			name: "size preflight rejection removes the temp directory",
			setup: func(t *testing.T) (string, *malcontent.Config) {
				t.Helper()
				layer := ociGzip(t, gzip.DefaultCompression, ociTar(t, ociFile{name: ociHelloName, body: []byte(ociHelloBody)}))
				oversized := ociBlobDesc(types.DockerLayer, layer)
				oversized.size = 1 << 30
				_, ref := ociServe(t, newOCIImageRegistry(t, [][]byte{layer, ociConfigBlob}, config, oversized))
				return ref, ociTestConfig(1 << 16)
			},
			wantErr: "image size exceeds maximum allowed size",
		},
		{
			name: "export over the size limit removes the temp directory",
			setup: func(t *testing.T) (string, *malcontent.Config) {
				t.Helper()
				layer := ociGzip(t, gzip.BestCompression, ociTar(t, ociFile{name: "zeros.bin", body: make([]byte, 1<<20)}))
				_, ref := ociServe(t, newOCIImageRegistry(t, [][]byte{layer, ociConfigBlob}, config, ociBlobDesc(types.DockerLayer, layer)))
				return ref, ociTestConfig(64 << 10)
			},
			wantErr: ociExportLimitErr,
		},
		{
			name: "rejected tar extraction removes the temp directory",
			setup: func(t *testing.T) (string, *malcontent.Config) {
				t.Helper()
				const artifactType types.MediaType = "application/vnd.malcontent.test.archive"
				blob := append(ociTar(t, ociFile{name: ociHelloName, body: []byte(ociHelloBody)}), "hidden payload"...)
				_, ref := ociServe(t, newOCIImageRegistry(t, [][]byte{blob, ociConfigBlob}, config, ociBlobDesc(artifactType, blob)))
				return ref, ociTestConfig(0)
			},
			wantErr: "extract image",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("TMPDIR", root)
			ref, c := tc.setup(t)

			dir, err := OCIWithConfig(t.Context(), ref, c)

			var want []string
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("OCIWithConfig: %v", err)
				}
				want = []string{filepath.Base(dir)}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error: got = %v, want containing %q", err, tc.wantErr)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatalf("read temp root: %v", err)
			}
			got := make([]string, 0, len(entries))
			for _, e := range entries {
				got = append(got, e.Name())
			}
			if !slices.Equal(got, want) {
				t.Errorf("temp root entries: got = %v, want = %v", got, want)
			}
			open, ok := ociOpenFilesUnder(t, root)
			if !ok {
				t.Log("descriptor check skipped: /proc/self/fd is unavailable")
				return
			}
			if len(open) != 0 {
				t.Errorf("open descriptors under the temp root: got = %v, want = none", open)
			}
		})
	}
}

// ociOpenFilesUnder lists the targets of this process's open descriptors that
// lie under root. ok is false where /proc/self/fd is unavailable.
func ociOpenFilesUnder(t *testing.T, root string) ([]string, bool) {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, false
	}
	prefixes := []string{root + string(filepath.Separator)}
	if resolved, err := filepath.EvalSymlinks(root); err == nil && resolved != root {
		prefixes = append(prefixes, resolved+string(filepath.Separator))
	}
	var open []string
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err != nil {
			continue // closed after the listing, e.g. the listing's own descriptor
		}
		for _, p := range prefixes {
			if strings.HasPrefix(target, p) {
				open = append(open, target)
				break
			}
		}
	}
	return open, true
}
