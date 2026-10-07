// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	zip "github.com/klauspost/compress/zip"
	"github.com/puzpuzpuz/xsync/v4"
)

// zipFoldCase enables the handling for case-folding filesystems until the test
// ends. Tests that call it must not call t.Parallel, because parallel tests
// rely on the platform default.
func zipFoldCase(t *testing.T) {
	t.Helper()
	prev := caseInsensitiveFS
	caseInsensitiveFS = true
	t.Cleanup(func() { caseInsensitiveFS = prev })
}

// zipRegularContents returns the sorted contents of every regular file
// beneath dir.
func zipRegularContents(t *testing.T, dir string) []string {
	t.Helper()
	r := openTestRoot(t, dir)
	var got []string
	err := fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, err := r.ReadFile(p)
		if err != nil {
			return err
		}
		got = append(got, string(data))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	slices.Sort(got)
	return got
}

// TestExtractZipCaseFoldingCollisions extracts with the case-folding handling
// enabled. A case-sensitive filesystem cannot fold names, so each collision is
// produced with names that match exactly, which is how a case-folding
// filesystem sees names such as META-INF/LICENSE and META-INF/license/.
func TestExtractZipCaseFoldingCollisions(t *testing.T) {
	zipFoldCase(t)

	const symlinkMode = fs.ModeSymlink | 0o777
	innerZip := string(zipSpecBytes(t, zip.Deflate, []zipSpecEntry{{name: "payload.txt", body: "nested payload"}}))

	// existing holds files written to the destination before extraction.
	// linkOut names a symlink placed in the destination that leads to a
	// missing path in an empty directory beside the root. Following the link
	// would create that path, so the directory must stay empty. A link that
	// resolves outside the root would instead make the entry be skipped.
	// nested names an archive to extract after ExtractZip returns, as
	// ExtractArchiveToTempDir does for each archive it finds. altTree is also
	// accepted when concurrent workers can finish in either order.
	tests := []struct {
		name         string
		entries      []zipSpecEntry
		existing     map[string]string
		linkOut      string
		nested       string
		wantTree     []string
		altTree      []string
		wantFiles    map[string]string
		wantContents []string
	}{
		{
			name:         "file entry whose path is an existing directory is written to a sibling name",
			entries:      []zipSpecEntry{{name: "docs/notes/"}, {name: "docs/notes/a.txt", body: "inner"}, {name: "docs/notes", body: "outer"}},
			wantTree:     []string{"docs/", "docs/notes/", "docs/notes/a.txt", "docs/notes_1"},
			wantFiles:    map[string]string{"docs/notes/a.txt": "inner", "docs/notes_1": "outer"},
			wantContents: []string{"inner", "outer"},
		},
		{
			name:     "every directory entry is created, including empty ones",
			entries:  []zipSpecEntry{{name: "one/"}, {name: "two/"}, {name: "three/sub/"}},
			wantTree: []string{"one/", "three/", "three/sub/", "two/"},
		},
		{
			name:         "colliding file entries keep both contents under distinct names",
			entries:      []zipSpecEntry{{name: "com/Foo.class", body: "first"}, {name: "com/Foo.class", body: "second"}},
			wantTree:     []string{"com/", "com/Foo.class", "com/Foo_1.class"},
			wantContents: []string{"first", "second"},
		},
		{
			name:         "symlink entry whose path holds a file is created under a sibling name",
			entries:      []zipSpecEntry{{name: "data.txt", body: "payload"}, {name: "other.txt", body: "other"}, {name: "data.txt", body: "other.txt", mode: symlinkMode}},
			wantTree:     []string{"data.txt", "data_1.txt -> other.txt", "other.txt"},
			wantFiles:    map[string]string{"data.txt": "payload", "data_1.txt": "other"},
			wantContents: []string{"other", "payload"},
		},
		{
			name:         "file already in the destination is kept and the entry gets a sibling name",
			entries:      []zipSpecEntry{{name: "top.txt", body: "new"}},
			existing:     map[string]string{"top.txt": "earlier"},
			wantTree:     []string{"top.txt", "top_1.txt"},
			wantFiles:    map[string]string{"top.txt": "earlier", "top_1.txt": "new"},
			wantContents: []string{"earlier", "new"},
		},
		{
			name:         "entry named like a symlink leading out of the root is written beside the link",
			entries:      []zipSpecEntry{{name: "linkdir", body: "shadow"}},
			linkOut:      "linkdir",
			wantTree:     []string{"linkdir -> ../outside/missing", "linkdir_1"},
			wantFiles:    map[string]string{"linkdir_1": "shadow"},
			wantContents: []string{"shadow"},
		},
		{
			name:         "entry beneath a symlink leading out of the root is written to a sibling directory",
			entries:      []zipSpecEntry{{name: "linkdir/x.txt", body: "beneath"}},
			linkOut:      "linkdir",
			wantTree:     []string{"linkdir -> ../outside/missing", "linkdir_1/", "linkdir_1/x.txt"},
			wantFiles:    map[string]string{"linkdir_1/x.txt": "beneath"},
			wantContents: []string{"beneath"},
		},
		{
			// Symlinks are created after every file, so the file always
			// claims the path before the link needs it as a directory.
			name:         "directory needed after a file of the same name is created under a sibling name",
			entries:      []zipSpecEntry{{name: "docs/guide", body: "guide"}, {name: "docs/other.txt", body: "other"}, {name: "docs/guide/link", body: "../other.txt", mode: symlinkMode}},
			wantTree:     []string{"docs/", "docs/guide", "docs/guide_1/", "docs/guide_1/link -> ../other.txt", "docs/other.txt"},
			wantFiles:    map[string]string{"docs/guide": "guide", "docs/guide_1/link": "other"},
			wantContents: []string{"guide", "other"},
		},
		{
			name: "every entry beneath a directory whose path holds a file shares one sibling directory",
			entries: []zipSpecEntry{
				{name: "META-INF/license/sub2/"},
				{name: "META-INF/license/a.txt", body: "a"},
				{name: "META-INF/license/sub/b.txt", body: "b"},
				{name: "META-INF/license/c.txt", body: "c"},
				{name: "META-INF/license/link", body: "a.txt", mode: symlinkMode},
			},
			existing: map[string]string{"META-INF/license": "earlier"},
			wantTree: []string{
				"META-INF/",
				"META-INF/license",
				"META-INF/license_1/",
				"META-INF/license_1/a.txt",
				"META-INF/license_1/c.txt",
				"META-INF/license_1/link -> a.txt",
				"META-INF/license_1/sub/",
				"META-INF/license_1/sub/b.txt",
				"META-INF/license_1/sub2/",
			},
			wantFiles: map[string]string{
				"META-INF/license":             "earlier",
				"META-INF/license_1/a.txt":     "a",
				"META-INF/license_1/sub/b.txt": "b",
				"META-INF/license_1/c.txt":     "c",
				"META-INF/license_1/link":      "a",
			},
			wantContents: []string{"a", "b", "c", "earlier"},
		},
		{
			name:     "renamed directory never merges into an existing sibling directory",
			entries:  []zipSpecEntry{{name: "META-INF/license/a.txt", body: "a"}},
			existing: map[string]string{"META-INF/license": "earlier", "META-INF/license_1/keep.txt": "kept"},
			wantTree: []string{
				"META-INF/",
				"META-INF/license",
				"META-INF/license_1/",
				"META-INF/license_1/keep.txt",
				"META-INF/license_2/",
				"META-INF/license_2/a.txt",
			},
			wantFiles:    map[string]string{"META-INF/license_1/keep.txt": "kept", "META-INF/license_2/a.txt": "a"},
			wantContents: []string{"a", "earlier", "kept"},
		},
		{
			name: "file and directory of the same name in one archive split once and keep every entry",
			entries: []zipSpecEntry{
				{name: "META-INF/license", body: "file"},
				{name: "META-INF/license/a.txt", body: "a"},
				{name: "META-INF/license/b.txt", body: "b"},
				{name: "META-INF/license/sub/c.txt", body: "c"},
			},
			wantTree: []string{
				"META-INF/",
				"META-INF/license",
				"META-INF/license_1/",
				"META-INF/license_1/a.txt",
				"META-INF/license_1/b.txt",
				"META-INF/license_1/sub/",
				"META-INF/license_1/sub/c.txt",
			},
			altTree: []string{
				"META-INF/",
				"META-INF/license/",
				"META-INF/license/a.txt",
				"META-INF/license/b.txt",
				"META-INF/license/sub/",
				"META-INF/license/sub/c.txt",
				"META-INF/license_1",
			},
			wantContents: []string{"a", "b", "c", "file"},
		},
		{
			name:         "nested archive beneath a renamed directory is still extracted by name",
			entries:      []zipSpecEntry{{name: "lib/app/inner.zip", body: innerZip}},
			existing:     map[string]string{"lib/app": "earlier"},
			nested:       "lib/app_1/inner.zip",
			wantTree:     []string{"lib/", "lib/app", "lib/app_1/", "lib/app_1/inner/", "lib/app_1/inner/payload.txt"},
			wantFiles:    map[string]string{"lib/app": "earlier", "lib/app_1/inner/payload.txt": "nested payload"},
			wantContents: []string{"earlier", "nested payload"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "case.zip")
			zipSpecWrite(t, src, zip.Deflate, tt.entries)
			parent := t.TempDir()
			d := filepath.Join(parent, "out")
			pr := openTestRoot(t, parent)
			for _, dir := range []string{"out", "outside"} {
				if err := pr.Mkdir(dir, 0o700); err != nil {
					t.Fatalf("mkdir %s: %v", filepath.Join(parent, dir), err)
				}
			}
			dr := openTestRoot(t, d)
			for name, body := range tt.existing {
				if err := dr.MkdirAll(filepath.Dir(name), 0o700); err != nil {
					t.Fatalf("mkdir for existing %s: %v", name, err)
				}
				if err := dr.WriteFile(name, []byte(body), 0o600); err != nil {
					t.Fatalf("write existing %s: %v", name, err)
				}
			}
			if tt.linkOut != "" {
				if err := dr.Symlink("../outside/missing", tt.linkOut); err != nil {
					t.Fatalf("symlink %s: %v", tt.linkOut, err)
				}
			}

			if err := ExtractZip(t.Context(), d, src); err != nil {
				t.Fatalf("ExtractZip error: got = %v, want = nil", err)
			}
			if tt.nested != "" {
				err := extractNestedArchive(t.Context(), malcontent.Config{}, d, tt.nested, xsync.NewMap[string, bool](), clog.FromContext(t.Context()), 1)
				if err != nil {
					t.Fatalf("extractNestedArchive(%s) error: got = %v, want = nil", tt.nested, err)
				}
			}

			if leaked, err := fs.ReadDir(pr.FS(), "outside"); err != nil || len(leaked) != 0 {
				t.Errorf("directory outside the root: got entries = %v (err %v), want = none", leaked, err)
			}
			got := zipSpecTree(t, d)
			if !slices.Equal(got, tt.wantTree) && (tt.altTree == nil || !slices.Equal(got, tt.altTree)) {
				t.Errorf("extracted tree: got = %q, want = %q (or %q)", got, tt.wantTree, tt.altTree)
			}
			if got := zipRegularContents(t, d); !slices.Equal(got, tt.wantContents) {
				t.Errorf("regular file contents: got = %q, want = %q", got, tt.wantContents)
			}
			for name, want := range tt.wantFiles {
				data, err := dr.ReadFile(name)
				if err != nil {
					t.Errorf("read %s: %v", name, err)
					continue
				}
				if string(data) != want {
					t.Errorf("contents of %s: got = %q, want = %q", name, data, want)
				}
			}
		})
	}
}

// TestZipExtractFileLogsRename checks that an entry written under a sibling
// name is logged with both names, which is the only record tying the renamed
// path to the entry, and that an entry written at its own path is not.
func TestZipExtractFileLogsRename(t *testing.T) {
	t.Parallel()

	const taken = "because the path is already taken"
	tests := []struct {
		name     string
		existing bool
		wantLog  string
	}{
		{name: "entry whose path is taken is logged with its new name", existing: true, wantLog: "writing top.txt as top_1.txt " + taken},
		{name: "entry written at its own path is not logged as renamed", existing: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := filepath.Join(t.TempDir(), "entry.zip")
			zipSpecWrite(t, src, zip.Deflate, []zipSpecEntry{{name: "top.txt", body: "new"}})
			rc, err := zip.OpenReader(src)
			if err != nil {
				t.Fatalf("OpenReader: %v", err)
			}
			defer rc.Close()

			root, err := openRoot(filepath.Join(t.TempDir(), "out"))
			if err != nil {
				t.Fatalf("openRoot: %v", err)
			}
			defer root.Close()
			if tt.existing {
				if err := root.WriteFile("top.txt", []byte("earlier"), 0o600); err != nil {
					t.Fatalf("write existing file: %v", err)
				}
			}

			var logs bytes.Buffer
			logger := clog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			if err := extractFile(t.Context(), rc.File[0], testEntryRoots(t, root), logger, &file.ArchiveCounter{}, newZipFoldedPaths(root)); err != nil {
				t.Fatalf("extractFile error: got = %v, want = nil", err)
			}

			got := logs.String()
			if tt.wantLog != "" && !strings.Contains(got, tt.wantLog) {
				t.Errorf("log: got = %q, want = containing %q", got, tt.wantLog)
			}
			if tt.wantLog == "" && strings.Contains(got, taken) {
				t.Errorf("log: got = %q, want = no rename message", got)
			}
		})
	}
}

// TestZipFoldedPathsShareRenamedDirectory resolves one renamed directory from
// many workers at once; every file must land in the same sibling directory.
func TestZipFoldedPathsShareRenamedDirectory(t *testing.T) {
	t.Parallel()

	root, err := openRoot(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatalf("openRoot: %v", err)
	}
	defer root.Close()
	if err := root.WriteFile("shared", []byte("file"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	const workers = 32
	paths := newZipFoldedPaths(root)
	names := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() {
			out, name, err := paths.createFile(fmt.Sprintf("shared/sub/f%d.txt", i))
			if err == nil {
				err = out.Close()
			}
			names[i], errs[i] = name, err
		})
	}
	wg.Wait()

	for i := range workers {
		if errs[i] != nil {
			t.Fatalf("createFile(shared/sub/f%d.txt) error: got = %v, want = nil", i, errs[i])
		}
		if want := fmt.Sprintf("shared_1/sub/f%d.txt", i); names[i] != want {
			t.Errorf("createFile(shared/sub/f%d.txt) name: got = %q, want = %q", i, names[i], want)
		}
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	top := make([]string, 0, len(entries))
	for _, e := range entries {
		top = append(top, e.Name())
	}
	if want := []string{"shared", "shared_1"}; !slices.Equal(top, want) {
		t.Errorf("root entries: got = %q, want = %q", top, want)
	}
}

// TestZipFoldedPathsDirectoryCase checks that directory names differing only
// in case resolve to the directory created for the first of them.
func TestZipFoldedPathsDirectoryCase(t *testing.T) {
	t.Parallel()

	root, err := openRoot(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatalf("openRoot: %v", err)
	}
	defer root.Close()
	paths := newZipFoldedPaths(root)

	// Each step depends on the directories the previous steps created.
	steps := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: ".", want: "."},
		{in: "Docs/Guide", want: "Docs/Guide"},
		{in: "docs/guide", want: "Docs/Guide"},
		{in: "DOCS/guide/Extra", want: "Docs/Guide/Extra"},
		{in: "docs/other", want: "Docs/other"},
		{in: "/etc", wantErr: true},
	}
	for _, s := range steps {
		got, err := paths.dir(s.in)
		if (err != nil) != s.wantErr {
			t.Fatalf("dir(%q) error: got = %v, want error = %v", s.in, err, s.wantErr)
		}
		if got != s.want {
			t.Errorf("dir(%q): got = %q, want = %q", s.in, got, s.want)
		}
	}
}

func TestZipCollisionNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		in        string
		wantFirst string
		wantLast  string
	}{
		{name: "name without an extension gets a plain suffix", in: "META-INF/LICENSE", wantFirst: "META-INF/LICENSE_1", wantLast: "META-INF/LICENSE_1024"},
		{name: "suffix goes before a single extension", in: "com/acme/Foo.class", wantFirst: "com/acme/Foo_1.class", wantLast: "com/acme/Foo_1024.class"},
		{name: "suffix goes before a compound archive extension", in: "lib/app.tar.gz", wantFirst: "lib/app_1.tar.gz", wantLast: "lib/app_1024.tar.gz"},
		{name: "dot file keeps its whole name as the stem", in: ".hidden", wantFirst: ".hidden_1", wantLast: ".hidden_1024"},
		{name: "versioned library name gets a plain suffix", in: "libfoo.so.1.2.3", wantFirst: "libfoo.so.1.2.3_1", wantLast: "libfoo.so.1.2.3_1024"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := slices.Collect(zipCollisionNames(tt.in))
			if len(got) != maxCollisionNames+1 {
				t.Fatalf("name count: got = %d, want = %d", len(got), maxCollisionNames+1)
			}
			if got[0] != tt.in || got[1] != tt.wantFirst || got[len(got)-1] != tt.wantLast {
				t.Errorf("names: got = %q, %q, ..., %q, want = %q, %q, ..., %q", got[0], got[1], got[len(got)-1], tt.in, tt.wantFirst, tt.wantLast)
			}
			seen := make(map[string]struct{}, len(got))
			for _, name := range got {
				if _, dup := seen[name]; dup {
					t.Errorf("duplicate name: got = %q twice, want = distinct names", name)
				}
				seen[name] = struct{}{}
				if filepath.Dir(name) != filepath.Dir(tt.in) {
					t.Errorf("directory of %q: got = %q, want = %q", name, filepath.Dir(name), filepath.Dir(tt.in))
				}
			}
		})
	}
}

// TestZipCollisionNamesStopsEarly checks that the sequence honors a consumer
// that stops early; a sequence that kept yielding would panic.
func TestZipCollisionNamesStopsEarly(t *testing.T) {
	t.Parallel()

	for _, want := range []int{1, 2} {
		got := 0
		for range zipCollisionNames("a.txt") {
			got++
			if got == want {
				break
			}
		}
		if got != want {
			t.Errorf("names consumed before stopping: got = %d, want = %d", got, want)
		}
	}
}
