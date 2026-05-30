// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// sizedManifestRegistry serves an OCI manifest whose layer and config sizes are
// fully attacker-controlled, including negative and overflow-inducing values,
// so the size-preflight can be exercised against hostile descriptors.
type sizedManifestRegistry struct {
	t            *testing.T
	manifestJSON []byte
	configBlob   []byte
	configDigest string
	layerBlob    []byte
	layerDigest  string
	blobHits     int32
}

func newSizedManifestRegistry(t *testing.T, layerSize, configSize int64) *sizedManifestRegistry {
	t.Helper()

	var layerRaw bytes.Buffer
	gz := gzip.NewWriter(&layerRaw)
	tw := tar.NewWriter(gz)
	body := []byte("hello-malcontent")
	hdr := &tar.Header{Name: "hello.txt", Mode: 0o644, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()
	layer := layerRaw.Bytes()
	layerDigest := sizedDigestOf(layer)

	configBlob := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:` + sizedDigestOf(body)[7:] + `"]}}`)
	configDigest := sizedDigestOf(configBlob)

	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.docker.distribution.manifest.v2+json",
		"config": map[string]any{
			"mediaType": "application/vnd.docker.container.image.v1+json",
			"size":      configSize,
			"digest":    configDigest,
		},
		"layers": []map[string]any{
			{
				"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
				"size":      layerSize,
				"digest":    layerDigest,
			},
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	return &sizedManifestRegistry{
		t:            t,
		manifestJSON: manifestJSON,
		configBlob:   configBlob,
		configDigest: configDigest,
		layerBlob:    layer,
		layerDigest:  layerDigest,
	}
}

func sizedDigestOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (h *sizedManifestRegistry) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", sizedDigestOf(h.manifestJSON))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(h.manifestJSON)
		case strings.Contains(r.URL.Path, "/blobs/"):
			atomic.AddInt32(&h.blobHits, 1)
			if strings.HasSuffix(r.URL.Path, h.configDigest) {
				_, _ = w.Write(h.configBlob)
				return
			}
			if strings.HasSuffix(r.URL.Path, h.layerDigest) {
				_, _ = w.Write(h.layerBlob)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// TestOCIHardening_SizePreflight_HostileDescriptorsRejected proves the
// size-preflight fails closed when a registry advertises a negative size or
// sizes whose unchecked sum would overflow int64 negative. A naive accumulator
// would let either case slip past the maxImageSize comparison.
func TestOCIHardening_SizePreflight_HostileDescriptorsRejected(t *testing.T) {
	cases := []struct {
		name       string
		layerSize  int64
		configSize int64
	}{
		{"negative layer size", -1, 16},
		{"negative config size", 16, -1},
		{"overflow to negative sum", math.MaxInt64, math.MaxInt64},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCleanHostSemaphores(t)
			reg := newSizedManifestRegistry(t, tc.layerSize, tc.configSize)
			srv := httptest.NewServer(reg.handler())
			defer srv.Close()

			c := &malcontent.Config{
				OCIPullTimeoutSeconds:    30,
				OCIRetryMaxAttempts:      1,
				OCIRetryMaxWindowSeconds: 5,
				OCIPerHostSlots:          2,
				MaxImageSize:             1 << 16, // 64 KiB
			}

			_, err := OCIWithConfig(context.Background(), hostPort(t, srv.URL)+"/foo:bar", c)
			if err == nil {
				t.Fatal("expected hostile-descriptor rejection, got nil")
			}
			if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
				t.Fatalf("expected size error, got %v", err)
			}
			if got := atomic.LoadInt32(&reg.blobHits); got != 0 {
				t.Fatalf("preflight should abort before blob fetch, got %d blob hits", got)
			}
		})
	}
}
