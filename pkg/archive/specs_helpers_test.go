// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"cmp"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// benignMarker stands in for a payload: a test passes when it reaches the
// extracted tree.
const benignMarker = "AUDITMARK_7d1e3b"

// tarSpec describes one entry of a tar stream tarSpecBytes writes.
type tarSpec struct {
	name, linkname, body string
	typeflag             byte
	pax                  map[string]string
}

// tarSpecBytes returns a tar stream of entries, ending with the
// end-of-archive marker when end is set.
func tarSpecBytes(t *testing.T, entries []tarSpec, end bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: cmp.Or(e.typeflag, tar.TypeReg), Linkname: e.linkname, Mode: 0o644, PAXRecords: e.pax}
		if hdr.Typeflag == tar.TypeReg || e.body != "" {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if _, err := io.WriteString(tw, e.body); err != nil {
			t.Fatalf("write body %q: %v", e.name, err)
		}
	}
	var err error
	if end {
		err = tw.Close()
	} else {
		err = tw.Flush()
	}
	if err != nil {
		t.Fatalf("finish tar: %v", err)
	}
	return buf.Bytes()
}

// arMember is one member of an ar archive arBytes writes.
type arMember struct {
	name string
	body []byte
}

// arBytes returns an ar archive, as .deb packages are, holding members.
func arBytes(members []arMember) []byte {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&b, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", m.name, "0", "0", "0", "100644", len(m.body))
		b.Write(m.body)
		if len(m.body)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// treeContents maps every path beneath dir to what it holds: a regular
// file's content, "-> target" for a symlink, and "/" for a directory.
func treeContents(t *testing.T, dir string) map[string]string {
	t.Helper()
	r := openTestRoot(t, dir)
	got := map[string]string{}
	err := fs.WalkDir(r.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case rel == ".":
		case d.Type()&fs.ModeSymlink != 0:
			target, err := r.Readlink(rel)
			if err != nil {
				return err
			}
			got[rel] = "-> " + target
		case d.IsDir():
			got[rel] = "/"
		default:
			data, err := r.ReadFile(rel)
			if err != nil {
				return err
			}
			got[rel] = string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return got
}

// wantTree fails unless dir holds exactly want, as treeContents reports it.
func wantTree(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	if got := treeContents(t, dir); !maps.Equal(got, want) {
		t.Errorf("tree of %s:\n got = %q\nwant = %q", dir, got, want)
	}
}

// testPaths returns entry paths on root, whose directory roots close when the
// test ends.
func testPaths(tb testing.TB, root *os.Root) *entryPaths {
	tb.Helper()
	return newEntryPaths(testEntryRoots(tb, root))
}

// testBudget returns a budget with a byte cap of maxBytes, where zero means
// no cap, and no ratio cap.
func testBudget(maxBytes int64) *budget {
	return &budget{
		archive: &file.ArchiveCounter{},
		tree:    &file.ArchiveCounter{MaxBytes: maxBytes},
	}
}

// withCaseFolding sets caseInsensitiveFS for the rest of the test, which
// must not run in parallel.
func withCaseFolding(t *testing.T, fold bool) {
	t.Helper()
	prev := caseInsensitiveFS
	caseInsensitiveFS = fold
	t.Cleanup(func() { caseInsensitiveFS = prev })
}
