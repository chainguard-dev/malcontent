// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	ociHelloName = "hello.txt"
	ociHelloBody = "hello-malcontent"
)

// ociConfigBlob is a minimal image config. Export never fetches the config, so
// tests may advertise any size for it without breaking extraction.
var ociConfigBlob = []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)

// ociFile is one regular file in a fixture tar.
type ociFile struct {
	name string
	body []byte
}

// ociTar returns an uncompressed tar holding files in order.
func ociTar(t *testing.T, files ...ociFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", f.name, err)
		}
		if _, err := tw.Write(f.body); err != nil {
			t.Fatalf("tar write %s: %v", f.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// ociGzip compresses b at the given gzip level.
func ociGzip(t *testing.T, level int, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		t.Fatalf("gzip writer: %v", err)
	}
	if _, err := gz.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// ociDesc is a manifest descriptor whose advertised size may differ from the
// blob it names.
type ociDesc struct {
	mediaType types.MediaType
	digest    string
	size      int64
}

// ociBlobDesc returns a descriptor that advertises b's real size.
func ociBlobDesc(mediaType types.MediaType, b []byte) ociDesc {
	return ociDesc{mediaType: mediaType, digest: digestOf(b), size: int64(len(b))}
}

// ociManifest renders a Docker schema 2 manifest from the given descriptors.
func ociManifest(t *testing.T, config ociDesc, layers ...ociDesc) []byte {
	t.Helper()
	descriptor := func(d ociDesc) map[string]any {
		return map[string]any{"mediaType": d.mediaType, "digest": d.digest, "size": d.size}
	}
	ls := make([]map[string]any, 0, len(layers))
	for _, l := range layers {
		ls = append(ls, descriptor(l))
	}
	b, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     types.DockerManifestSchema2,
		"config":        descriptor(config),
		"layers":        ls,
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return b
}

// ociFixtureRegistry serves one manifest and a set of blobs over the OCI
// distribution API. A nonzero manifestStatus fails every manifest request with
// that status instead.
type ociFixtureRegistry struct {
	manifest       []byte
	blobs          map[string][]byte
	manifestStatus int

	blobHits atomic.Int32

	mu            sync.Mutex
	manifestTimes []time.Time
}

var _ http.Handler = (*ociFixtureRegistry)(nil)

// newOCIImageRegistry serves the manifest built from config and layers, plus
// every blob in blobs keyed by its digest.
func newOCIImageRegistry(t *testing.T, blobs [][]byte, config ociDesc, layers ...ociDesc) *ociFixtureRegistry {
	t.Helper()
	reg := &ociFixtureRegistry{
		manifest: ociManifest(t, config, layers...),
		blobs:    make(map[string][]byte, len(blobs)),
	}
	for _, b := range blobs {
		reg.blobs[digestOf(b)] = b
	}
	return reg
}

// ServeHTTP implements the ping, manifest, and blob endpoints.
func (r *ociFixtureRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.URL.Path == "/v2/":
		w.WriteHeader(http.StatusOK)
	case strings.Contains(req.URL.Path, "/manifests/"):
		r.mu.Lock()
		r.manifestTimes = append(r.manifestTimes, time.Now())
		r.mu.Unlock()
		if r.manifestStatus != 0 {
			w.WriteHeader(r.manifestStatus)
			return
		}
		w.Header().Set("Content-Type", string(types.DockerManifestSchema2))
		w.Header().Set("Docker-Content-Digest", digestOf(r.manifest))
		_, _ = w.Write(r.manifest)
	case strings.Contains(req.URL.Path, "/blobs/"):
		r.blobHits.Add(1)
		b, ok := r.blobs[path.Base(req.URL.Path)]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// manifestRequests returns the arrival time of every manifest request so far.
func (r *ociFixtureRegistry) manifestRequests() []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.manifestTimes)
}

// ociServe serves reg on a loopback server for the rest of the test and returns
// the server and an image reference into it.
func ociServe(t *testing.T, reg http.Handler) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	return srv, hostPort(t, srv.URL) + "/fixture:latest"
}

// ociTestConfig bounds the transport for loopback pulls and names a keepalive
// policy so the unset-policy warning stays quiet.
func ociTestConfig(maxImageSize int64) *malcontent.Config {
	return &malcontent.Config{
		MaxImageSize:             maxImageSize,
		OCIPullTimeoutSeconds:    30,
		OCIRetryMaxAttempts:      1,
		OCIRetryMaxWindowSeconds: 5,
		OCIPerHostSlots:          2,
		OCIKeepalivePolicy:       malcontent.KeepalivePolicyGoDefault,
	}
}

// ociAssertHelloExtracted checks that dir holds exactly hello.txt with the
// fixture body, and nothing else (in particular, not the exported tarball).
func ociAssertHelloExtracted(t *testing.T, dir string) {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open extraction dir: %v", err)
	}
	defer r.Close()
	entries, err := fs.ReadDir(r.FS(), ".")
	if err != nil {
		t.Fatalf("read extraction dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{ociHelloName}; !slices.Equal(names, want) {
		t.Fatalf("extracted entries: got = %v, want = %v", names, want)
	}
	got, err := r.ReadFile(ociHelloName)
	if err != nil {
		t.Fatalf("read %s: %v", ociHelloName, err)
	}
	if string(got) != ociHelloBody {
		t.Errorf("%s: got = %q, want = %q", ociHelloName, got, ociHelloBody)
	}
}

// ociWarnRecorder is a slog.Handler that keeps the message of every record at
// WARN or above.
type ociWarnRecorder struct {
	mu   sync.Mutex
	msgs []string
}

var _ slog.Handler = (*ociWarnRecorder)(nil)

func (r *ociWarnRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *ociWarnRecorder) Handle(_ context.Context, rec slog.Record) error {
	if rec.Level < slog.LevelWarn {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, rec.Message)
	return nil
}

func (r *ociWarnRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *ociWarnRecorder) WithGroup(string) slog.Handler { return r }

// count returns how many recorded warnings contain substr.
func (r *ociWarnRecorder) count(substr string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, m := range r.msgs {
		if strings.Contains(m, substr) {
			n++
		}
	}
	return n
}

// ociResetOnce rearms a package-level one-shot warning for the test and again
// afterwards, so the warning can be observed without leaking state into other
// tests. Callers must not run in parallel.
func ociResetOnce(t *testing.T, once *sync.Once) {
	t.Helper()
	*once = sync.Once{}
	t.Cleanup(func() { *once = sync.Once{} })
}
