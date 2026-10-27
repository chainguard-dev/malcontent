// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// ociTestEntry is one entry of a test layer. A zero typeflag means a regular
// file holding body.
type ociTestEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

// ociDirEntry, ociLinkEntry, and ociHardlinkEntry build the other entry kinds.
func ociDirEntry(entry string) ociTestEntry { return ociTestEntry{name: entry, typeflag: tar.TypeDir} }

func ociLinkEntry(entry, target string) ociTestEntry {
	return ociTestEntry{name: entry, typeflag: tar.TypeSymlink, linkname: target}
}

func ociHardlinkEntry(entry, target string) ociTestEntry {
	return ociTestEntry{name: entry, typeflag: tar.TypeLink, linkname: target}
}

// ociTestLayer returns a gzip layer holding entries in order.
func ociTestLayer(t *testing.T, entries ...ociTestEntry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Linkname: e.linkname, Mode: 0o644, Format: tar.FormatPAX}
		switch e.typeflag {
		case 0:
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(e.body))
		case tar.TypeDir:
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %q: %v", e.name, err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("tar write %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	b := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatalf("build layer: %v", err)
	}
	return layer
}

// ociTestImage stacks layers, lowest first, on an empty image.
func ociTestImage(t *testing.T, layers ...[]ociTestEntry) v1.Image {
	t.Helper()
	ls := make([]v1.Layer, 0, len(layers))
	for _, entries := range layers {
		ls = append(ls, ociTestLayer(t, entries...))
	}
	img, err := mutate.AppendLayers(empty.Image, ls...)
	if err != nil {
		t.Fatalf("append layers: %v", err)
	}
	return img
}

// ociTestRegistry serves an in-process registry for the rest of the test and
// returns its host:port.
func ociTestRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(slog.NewLogLogger(slog.DiscardHandler, slog.LevelInfo))))
	t.Cleanup(srv.Close)
	return hostPort(t, srv.URL)
}

// ociPushImage pushes img to ref.
func ociPushImage(t *testing.T, ref string, img v1.Image) {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatalf("parse %q: %v", ref, err)
	}
	if err := remote.Write(r, img, remote.WithContext(t.Context())); err != nil {
		t.Fatalf("push %s: %v", ref, err)
	}
}

// ociPushIndex pushes idx to ref.
func ociPushIndex(t *testing.T, ref string, idx v1.ImageIndex) {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatalf("parse %q: %v", ref, err)
	}
	if err := remote.WriteIndex(r, idx, remote.WithContext(t.Context())); err != nil {
		t.Fatalf("push index %s: %v", ref, err)
	}
}

// ociListDir describes everything below dir by slash path: "dir" for a
// directory, "link:<target>" for a symlink, and "file:<contents>" otherwise.
func ociListDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	got := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			got[rel] = "link:" + target
		case d.IsDir():
			got[rel] = "dir"
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			got[rel] = "file:" + string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return got
}

// ociAssertTree fails the test unless dir holds exactly want.
func ociAssertTree(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	got := ociListDir(t, dir)
	if maps.Equal(got, want) {
		return
	}
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if g, ok := got[k]; !ok {
			t.Errorf("%s: missing, want %q", k, want[k])
		} else if g != want[k] {
			t.Errorf("%s: got %q, want %q", k, g, want[k])
		}
	}
	for _, k := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[k]; !ok {
			t.Errorf("%s: unexpected %q", k, got[k])
		}
	}
}
