// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"container/heap"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/minio/sha256-simd"
	"github.com/puzpuzpuz/xsync/v4"
)

// queueTestEntry is one file of a generated archive.
type queueTestEntry struct {
	name string
	data []byte
}

func queueTestTarGz(t *testing.T, entries ...queueTestEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("tar header %s: %v", e.name, err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatalf("tar write %s: %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func queueTestZip(t *testing.T, entries ...queueTestEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("zip create %s: %v", e.name, err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatalf("zip write %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func queueTestGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func queueTestZlib(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// queueTestExtractedKeys returns the report keys of the files that
// ExtractArchiveToTempDir leaves for path, the files a scan of path reports.
func queueTestExtractedKeys(t *testing.T, c malcontent.Config, path string) []string {
	t.Helper()
	dir, err := archive.ExtractArchiveToTempDir(t.Context(), c, path)
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	root := resolveDir(dir)
	files, err := findFilesRecursively(t.Context(), root)
	if err != nil {
		t.Fatalf("findFilesRecursively: %v", err)
	}
	keys := make([]string, 0, len(files))
	for _, f := range files {
		keys = append(keys, archiveEntryKey(path, strings.TrimPrefix(f, root), nil))
	}
	slices.Sort(keys)
	return keys
}

func TestProcessPathReportsWhatExtractionLeaves(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)

	text := []byte("body { color: red; }\n")
	deepest := queueTestTarGz(t, queueTestEntry{"f.txt", []byte("deep\n")})
	middle := queueTestTarGz(t, queueTestEntry{"l3.tar.gz", deepest})
	top := queueTestTarGz(t, queueTestEntry{"l2.tar.gz", middle})
	corrupt := append([]byte{0x1f, 0x8b, 0x08, 0x00}, bytes.Repeat([]byte{0xff}, 64)...)

	tests := []struct {
		name     string
		file     string
		data     []byte
		maxDepth int
	}{
		{
			name: "nested gzip beside a file of the name it extracts to gets a numbered directory",
			file: "site.tar.gz",
			data: queueTestTarGz(t,
				queueTestEntry{"web/demo.css", text},
				queueTestEntry{"web/demo.css.gz", queueTestGzip(t, text)},
			),
		},
		{
			name: "skipped empty file still claims its name from a nested archive beside it",
			file: "empty.tar.gz",
			data: queueTestTarGz(t,
				queueTestEntry{"web/empty.txt", nil},
				queueTestEntry{"web/empty.txt.gz", queueTestGzip(t, text)},
				queueTestEntry{"web/notes.txt", text},
				queueTestEntry{"web/notes.txt.gz", queueTestGzip(t, []byte("notes\n"))},
			),
		},
		{
			name:     "archives past the depth limit are kept and scanned as files",
			file:     "deep.tar.gz",
			data:     queueTestTarGz(t, queueTestEntry{"deep/l1.tar.gz", top}),
			maxDepth: 2,
		},
		{
			name: "a nested archive that fails to extract is kept and scanned",
			file: "broken.tar.gz",
			data: queueTestTarGz(t,
				queueTestEntry{"bad.tar.gz", corrupt},
				queueTestEntry{"good.txt", text},
			),
		},
		{
			name: "zlib objects below .git are extracted but never reported",
			file: "repo.tar.gz",
			data: queueTestTarGz(t,
				queueTestEntry{"repo/.git/objects/ab/cdef0123", queueTestZlib(t, []byte("blob 5\x00hello"))},
				queueTestEntry{"repo/main.sh", []byte("#!/bin/sh\necho hi\n")},
			),
		},
		{
			name: "archives in different directories keep the names extracting them in order gives",
			file: "dirs.tar.gz",
			data: queueTestTarGz(t,
				queueTestEntry{"a/x", text},
				queueTestEntry{"a/x.gz", queueTestGzip(t, text)},
				queueTestEntry{"a/x.tar.gz", queueTestTarGz(t, queueTestEntry{"in.txt", text})},
				queueTestEntry{"b/x.gz", queueTestGzip(t, []byte("b\n"))},
				queueTestEntry{"b/x.zip", queueTestZip(t, queueTestEntry{"z.txt", text})},
				queueTestEntry{"c/d.gz", queueTestGzip(t, []byte("c\n"))},
				queueTestEntry{"c/d/x.gz", queueTestGzip(t, []byte("cd\n"))},
			),
		},
		{
			name: "a gzip stream without an archive name is extracted",
			file: "payload",
			data: queueTestGzip(t, text),
		},
		{
			name: "zip archives nest like tar archives",
			file: "bundle.zip",
			data: queueTestZip(t,
				queueTestEntry{"lib/inner.zip", queueTestZip(t, queueTestEntry{"a.txt", text})},
				queueTestEntry{"lib/inner", text},
				queueTestEntry{"lib/x.gz", queueTestGzip(t, text)},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := scanTestWriteFile(t, filepath.Join(dir, tt.file), tt.data)
			c := malcontent.Config{Concurrency: 8, MaxDepth: tt.maxDepth, Rules: yrs, RuleFS: rfs}
			want := queueTestExtractedKeys(t, c, path)

			// The queue examines files concurrently, so the outcome must not
			// depend on scheduling: repeat it.
			for range 3 {
				logger, _ := scanTestLogger()
				r := initializeReport(nil)
				scanInfo := scanPathInfo{originalPath: dir, effectivePath: dir}
				if err := processPath(t.Context(), path, scanInfo, c, r, make(chan matchResult, 1), &sync.Once{}, logger); err != nil {
					t.Fatalf("processPath: %v", err)
				}
				if got := scanTestKeys(r.Files); !slices.Equal(got, want) {
					t.Fatalf("report keys:\ngot  = %q\nwant = %q", got, want)
				}
			}
		})
	}
}

func TestTaskHeapOrdersLargestFirst(t *testing.T) {
	t.Parallel()
	h := &taskHeap{}
	for _, tk := range []task{
		{path: "b", size: 10},
		{path: "c", size: 1},
		{path: "a", size: 10},
		{path: "d", size: 30},
		{path: "e", size: 0},
	} {
		heap.Push(h, tk)
	}
	var got []string
	for h.Len() > 0 {
		got = append(got, heap.Pop(h).(task).path)
	}
	if want := []string{"d", "a", "b", "c", "e"}; !slices.Equal(got, want) {
		t.Errorf("pop order: got = %v, want = %v", got, want)
	}
}

func TestWalkedFilesRecordsSizes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	small := scanTestWriteFile(t, filepath.Join(dir, "small"), []byte("ab"))
	large := scanTestWriteFile(t, filepath.Join(dir, "large"), bytes.Repeat([]byte("x"), 100))
	missing := filepath.Join(dir, "missing")

	got := walkedFiles([]string{small, large, missing})
	want := []walkedFile{{small, 2}, {large, 100}, {missing, 0}}
	if !slices.Equal(got, want) {
		t.Errorf("walked files: got = %v, want = %v", got, want)
	}
}

func TestRunQueueReturnsTheFirstFailure(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	dir := t.TempDir()
	clean := scanTestWriteFile(t, filepath.Join(dir, "locale.sh"), []byte(scanTestLocaleScript))
	missing := filepath.Join(dir, "vanished.sh")

	logger, _ := scanTestLogger()
	r := initializeReport(nil)
	c := malcontent.Config{Concurrency: 1, Rules: yrs, RuleFS: rfs}
	err := runQueue(t.Context(), walkedFiles([]string{clean, missing}), 1, scanPathInfo{originalPath: dir, effectivePath: dir}, c, r, make(chan matchResult, 1), &sync.Once{}, logger)
	if err == nil || !strings.Contains(err.Error(), "vanished.sh") {
		t.Fatalf("error: got = %v, want one naming vanished.sh", err)
	}
}

func TestRunQueueStopsWhenCanceled(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	dir := t.TempDir()
	names := []string{"a.sh", "b.sh", "c.sh"}
	paths := make([]string, 0, len(names))
	for _, name := range names {
		paths = append(paths, scanTestWriteFile(t, filepath.Join(dir, name), []byte(scanTestLocaleScript)))
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	logger, _ := scanTestLogger()
	r := initializeReport(nil)
	c := malcontent.Config{Concurrency: 2, Rules: yrs, RuleFS: rfs}
	if err := runQueue(ctx, walkedFiles(paths), 2, scanPathInfo{originalPath: dir, effectivePath: dir}, c, r, make(chan matchResult, 1), &sync.Once{}, logger); err != nil {
		t.Fatalf("runQueue: got = %v, want = nil", err)
	}
	if got := r.Files.Size(); got != 0 {
		t.Errorf("reports after cancellation: got = %d, want = 0", got)
	}
}

// queueTestCorruptGzip is a gzip header followed by data that does not
// inflate, so extracting it fails.
func queueTestCorruptGzip(size int) []byte {
	return append([]byte{0x1f, 0x8b, 0x08, 0x00}, bytes.Repeat([]byte{0xff}, size)...)
}

// queueTestQueue returns a queue for driving its steps directly, its context
// canceled when canceled is set.
func queueTestQueue(t *testing.T, c malcontent.Config, canceled bool) *scanQueue {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	if canceled {
		cancel()
	}
	logger, _ := scanTestLogger()
	q := &scanQueue{
		ctx:       ctx,
		cancel:    cancel,
		c:         c,
		r:         initializeReport(nil),
		matchChan: make(chan matchResult, 1),
		matchOnce: &sync.Once{},
		logger:    logger,
		open:      map[*archiveScan]struct{}{},
	}
	q.wake = sync.NewCond(&q.mu)
	return q
}

// queueTestOpenArchive extracts the archive at path as openArchive does and
// returns it with the files extraction produced. Its directory is removed
// when the test ends.
func queueTestOpenArchive(t *testing.T, c malcontent.Config, path string) (*archiveScan, []archive.TreeFile) {
	t.Helper()
	tree, err := archive.OpenTree(t.Context(), c, path)
	if err != nil {
		t.Fatalf("OpenTree: %v", err)
	}
	t.Cleanup(func() { _ = tree.Close() })
	files, err := tree.Files(tree.Dir())
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	a := &archiveScan{
		path:        path,
		displayPath: path,
		tree:        tree,
		tmpRoot:     resolveDir(tree.Dir()),
		frs:         xsync.NewMap[string, *malcontent.FileReport](),
	}
	return a, files
}

// queueTestBatch returns the batch of files, the first extraction of a, with
// the nested archives among them found as runEntry finds them.
func queueTestBatch(t *testing.T, a *archiveScan, files []archive.TreeFile) *treeBatch {
	t.Helper()
	b := &treeBatch{files: files, found: make([]*foundArchive, len(files)), depth: 1, lineage: a.tree.Root()}
	b.pending.Store(int64(len(files)))
	for i, f := range files {
		path := filepath.Join(a.tmpRoot, f.Rel)
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		s := sniffFile(t.Context(), path, fi)
		if n, ok := a.tree.Nested(f.Rel, fi.Size(), s.kind); ok {
			b.found[i] = &foundArchive{n: n, digest: sha256.Sum256(s.content.Bytes())}
		}
		s.close()
	}
	return b
}

func TestRunEntrySkipsWorkAfterStopOrFailure(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	c := malcontent.Config{Rules: yrs, RuleFS: rfs}
	data := queueTestTarGz(t, queueTestEntry{"run.sh", []byte("#!/bin/sh\necho hi\n")})

	tests := []struct {
		name       string
		canceled   bool
		failed     bool
		wantStored int
	}{
		{name: "an entry is scanned and its report kept", wantStored: 1},
		{name: "a canceled scan examines no further entries", canceled: true},
		{name: "a failed archive examines no further entries", failed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := scanTestWriteFile(t, filepath.Join(t.TempDir(), "a.tar.gz"), data)
			q := queueTestQueue(t, c, tt.canceled)
			a, files := queueTestOpenArchive(t, c, path)
			if tt.failed {
				a.fail(errors.New("earlier failure"))
			}
			// Another task holds the archive open, so it does not complete.
			a.pending.Store(2)

			q.runEntry(task{path: filepath.Join(a.tmpRoot, files[0].Rel), size: files[0].Size, arc: a, entry: treeEntry{rel: files[0].Rel}})
			if got := a.frs.Size(); got != tt.wantStored {
				t.Errorf("reports kept: got = %d, want = %d", got, tt.wantStored)
			}
		})
	}
}

func TestRunGroupSkipsExtractionAfterStopOrFailure(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	c := malcontent.Config{Rules: yrs, RuleFS: rfs}
	data := queueTestTarGz(t, queueTestEntry{"inner.tar.gz", queueTestTarGz(t, queueTestEntry{"in.txt", []byte("inner\n")})})

	tests := []struct {
		name      string
		canceled  bool
		failed    bool
		wantTasks int
	}{
		{name: "a nested archive is extracted and its files queued", wantTasks: 1},
		{name: "a canceled scan extracts no further archives", canceled: true},
		{name: "a failed archive extracts no further archives", failed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := scanTestWriteFile(t, filepath.Join(t.TempDir(), "outer.tar.gz"), data)
			q := queueTestQueue(t, c, tt.canceled)
			a, files := queueTestOpenArchive(t, c, path)
			b := queueTestBatch(t, a, files)
			if b.found[0] == nil {
				t.Fatalf("fixture precondition: got no nested archive in %v, want inner.tar.gz", files)
			}
			if tt.failed {
				a.fail(errors.New("earlier failure"))
			}
			// Another task holds the archive open, so it does not complete.
			a.pending.Store(2)

			q.runGroup(a, &extractGroup{batch: b, files: []int{0}})
			_, err := os.Stat(filepath.Join(a.tmpRoot, "inner"))
			if got, want := err == nil, tt.wantTasks > 0; got != want {
				t.Errorf("extraction directory created: got = %t, want = %t", got, want)
			}
			if got := len(q.tasks); got != tt.wantTasks {
				t.Errorf("queued tasks: got = %d, want = %d", got, tt.wantTasks)
			}
		})
	}
}

func TestRunEntryRecordsArchiveFailures(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	data := queueTestTarGz(t, queueTestEntry{"run.sh", []byte("#!/bin/sh\necho hi\n")})

	tests := []struct {
		name        string
		remove      bool // remove the extracted file before it is examined
		lock        bool // make the extracted file unreadable before it is examined
		kept        bool // examine the file as one nested extraction left in place
		includeData bool
		wantIs      error
		wantPrefix  string
	}{
		{
			name:   "an extracted file that is gone fails the archive",
			remove: true,
			wantIs: fs.ErrNotExist,
		},
		{
			name:       "an extracted file whose type cannot be determined fails the archive",
			lock:       true,
			wantIs:     fs.ErrPermission,
			wantPrefix: "extract to temp: failed to walk directory: failed to determine file type: ",
		},
		{
			name:        "a file left by nested extraction that cannot be scanned fails the archive",
			lock:        true,
			kept:        true,
			includeData: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.lock && os.Geteuid() == 0 {
				t.Skip("file permissions do not restrict root")
			}
			c := malcontent.Config{IncludeDataFiles: tt.includeData, Rules: yrs, RuleFS: rfs}
			path := scanTestWriteFile(t, filepath.Join(t.TempDir(), "a.tar.gz"), data)
			q := queueTestQueue(t, c, false)
			a, files := queueTestOpenArchive(t, c, path)
			e := treeEntry{rel: files[0].Rel}
			if !tt.kept {
				e.batch = queueTestBatch(t, a, files)
			}
			target := filepath.Join(a.tmpRoot, files[0].Rel)
			if tt.remove {
				if err := os.Remove(target); err != nil {
					t.Fatalf("remove: %v", err)
				}
			}
			if tt.lock {
				if err := os.Chmod(target, 0); err != nil {
					t.Fatalf("chmod: %v", err)
				}
			}
			// Another task holds the archive open, so it does not complete.
			a.pending.Store(2)

			q.runEntry(task{path: target, size: files[0].Size, arc: a, entry: e})
			err := a.failed()
			if err == nil {
				t.Fatalf("archive failure: got = nil, want an error")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("archive failure: got = %v, want errors.Is %v", err, tt.wantIs)
			}
			if !strings.HasPrefix(err.Error(), tt.wantPrefix) {
				t.Errorf("archive failure: got = %q, want prefix %q", err.Error(), tt.wantPrefix)
			}
			if got := a.frs.Size(); got != 0 {
				t.Errorf("reports kept: got = %d, want = 0", got)
			}
		})
	}
}

func TestProcessPathReportsNestedExtractionFailures(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	corrupt := queueTestCorruptGzip(64)

	tests := []struct {
		name       string
		data       []byte
		wantPrefix string
	}{
		{
			name: "a nested archive that fails to extract is named by the extraction",
			data: queueTestTarGz(t,
				queueTestEntry{"bad.tar.gz", corrupt},
				queueTestEntry{"good.txt", []byte("good\n")},
			),
			wantPrefix: "extract to temp: failed to walk directory: failed to extract archive: ",
		},
		{
			name:       "an archive that fails inside a nested archive is named as a nested file",
			data:       queueTestTarGz(t, queueTestEntry{"l1.tar.gz", queueTestTarGz(t, queueTestEntry{"bad.tar.gz", corrupt})}),
			wantPrefix: "extract to temp: failed to walk directory: process nested file " + filepath.Join("l1", "bad.tar.gz") + ": failed to extract archive: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := scanTestWriteFile(t, filepath.Join(dir, "outer.tar.gz"), tt.data)
			c := malcontent.Config{Concurrency: 4, ExitExtraction: true, Rules: yrs, RuleFS: rfs}
			// The scan reports the failure as ExtractArchiveToTempDir does.
			_, oracle := archive.ExtractArchiveToTempDir(t.Context(), c, path)
			if oracle == nil {
				t.Fatalf("fixture precondition: ExtractArchiveToTempDir: got no error, want an extraction failure")
			}

			logger, _ := scanTestLogger()
			r := initializeReport(nil)
			scanInfo := scanPathInfo{originalPath: dir, effectivePath: dir}
			err := processPath(t.Context(), path, scanInfo, c, r, make(chan matchResult, 1), &sync.Once{}, logger)
			if err == nil {
				t.Fatalf("processPath: got = nil, want the extraction failure")
			}
			if want := "extract to temp: " + oracle.Error(); err.Error() != want {
				t.Errorf("error: got = %q, want = %q", err.Error(), want)
			}
			if !strings.HasPrefix(err.Error(), tt.wantPrefix) {
				t.Errorf("error: got = %q, want prefix %q", err.Error(), tt.wantPrefix)
			}
			if got := r.Files.Size(); got != 0 {
				t.Errorf("reports of the failed archive: got = %d, want = 0", got)
			}
		})
	}
}

func TestProcessPathAppliesExitCriteriaToArchives(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	flagged := queueTestTarGz(t, queueTestEntry{"run.sh", []byte(diffTestShellPayload("flagged"))})
	clean := queueTestTarGz(t, queueTestEntry{"locale.sh", []byte(scanTestLocaleScript)})

	tests := []struct {
		name      string
		data      []byte
		firstHit  bool
		firstMiss bool
		wantMatch bool
	}{
		{name: "a flagged archive meets the first-hit criterion", data: flagged, firstHit: true, wantMatch: true},
		{name: "a clean archive does not meet the first-hit criterion", data: clean, firstHit: true},
		{name: "a clean archive meets the first-miss criterion", data: clean, firstMiss: true, wantMatch: true},
		{name: "a flagged archive does not meet the first-miss criterion", data: flagged, firstMiss: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := scanTestWriteFile(t, filepath.Join(dir, "pkg.tar.gz"), tt.data)
			c := malcontent.Config{Concurrency: 2, ExitFirstHit: tt.firstHit, ExitFirstMiss: tt.firstMiss, Rules: yrs, RuleFS: rfs}
			logger, _ := scanTestLogger()
			r := initializeReport(nil)
			matchChan := make(chan matchResult, 1)
			scanInfo := scanPathInfo{originalPath: dir, effectivePath: dir}
			err := processPath(t.Context(), path, scanInfo, c, r, matchChan, &sync.Once{}, logger)
			if got := errors.Is(err, ErrMatchedCondition); got != tt.wantMatch {
				t.Errorf("exit criterion met: got = %t (%v), want = %t", got, err, tt.wantMatch)
			}
			if got := len(matchChan) == 1; got != tt.wantMatch {
				t.Errorf("match queued: got = %t, want = %t", got, tt.wantMatch)
			}
		})
	}
}

func TestProcessPathStopsRecordingArchiveReportsOnceCanceled(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	dir := t.TempDir()
	path := scanTestWriteFile(t, filepath.Join(dir, "pkg.tar.gz"), queueTestTarGz(t,
		queueTestEntry{"a.sh", []byte(diffTestShellPayload("a"))},
		queueTestEntry{"b.sh", []byte(diffTestShellPayload("b"))},
	))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Rendering the first report cancels the scan.
	renderer := &scanTestRenderer{onFile: func(context.Context) { cancel() }}
	c := malcontent.Config{Concurrency: 2, Renderer: renderer, Rules: yrs, RuleFS: rfs}
	logger, _ := scanTestLogger()
	r := initializeReport(nil)
	scanInfo := scanPathInfo{originalPath: dir, effectivePath: dir}
	if err := processPath(ctx, path, scanInfo, c, r, make(chan matchResult, 1), &sync.Once{}, logger); err != nil {
		t.Fatalf("processPath: %v", err)
	}
	if got := len(renderer.rendered()); got != 1 {
		t.Errorf("reports rendered: got = %d, want = 1", got)
	}
	if got := r.Files.Size(); got != 1 {
		t.Errorf("reports recorded: got = %d, want = 1", got)
	}
}

func TestCompleteArchiveRecordsReports(t *testing.T) {
	t.Parallel()
	const display = "/scans/pkg.tar"
	clean := func() *malcontent.FileReport { return &malcontent.FileReport{Path: display + " ∴ /ok.sh"} }

	tests := []struct {
		name      string
		frs       map[string]*malcontent.FileReport
		canceled  bool
		firstMiss bool
		wantKeys  []string
	}{
		{
			name:     "reports are recorded under the archive's path, without empty keys or missing reports",
			frs:      map[string]*malcontent.FileReport{"/ok.sh": clean(), "": clean(), "/missing.sh": nil},
			wantKeys: []string{archiveEntryKey(display, "/ok.sh", nil)},
		},
		{
			name:      "a canceled scan records nothing and applies no exit criterion",
			frs:       map[string]*malcontent.FileReport{"/ok.sh": clean()},
			canceled:  true,
			firstMiss: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			q := queueTestQueue(t, malcontent.Config{ExitFirstMiss: tt.firstMiss}, tt.canceled)
			// The archive's tree is not open in q, so completing it removes
			// nothing.
			a := &archiveScan{path: display, displayPath: display, frs: xsync.NewMap[string, *malcontent.FileReport]()}
			for k, fr := range tt.frs {
				a.frs.Store(k, fr)
			}

			q.completeArchive(a)
			if got := scanTestKeys(q.r.Files); !slices.Equal(got, tt.wantKeys) {
				t.Errorf("recorded keys: got = %q, want = %q", got, tt.wantKeys)
			}
			if q.err != nil || len(q.matchChan) != 0 {
				t.Errorf("exit criterion: got error %v and %d queued matches, want neither", q.err, len(q.matchChan))
			}
		})
	}
}

func TestCompleteArchiveRendersAfterRemovingItsTree(t *testing.T) {
	// Not parallel: points TMPDIR at a directory the test inspects, and scans
	// with rules other than the bundled ones, which replaces the
	// package-level scanner pool.
	_, rfs := scanTestRules(t)
	marker := scanTestMarkerRules(t)
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := scanTestWriteFile(t, filepath.Join(dir, "pkg.tar.gz"), queueTestTarGz(t,
		queueTestEntry{"marker.sh", []byte("#!/bin/sh\necho scan-test-marker\n")},
	))
	t.Setenv("TMPDIR", tmp)

	var leftovers []string
	renderer := &scanTestRenderer{onFile: func(context.Context) {
		entries, err := os.ReadDir(tmp)
		if err != nil {
			t.Errorf("ReadDir(%q): %v", tmp, err)
		}
		for _, e := range entries {
			leftovers = append(leftovers, e.Name())
		}
	}}
	c := malcontent.Config{Concurrency: 2, Renderer: renderer, Rules: marker, RuleFS: rfs}
	logger, _ := scanTestLogger()
	r := initializeReport(nil)
	scanInfo := scanPathInfo{originalPath: dir, effectivePath: dir}
	if err := processPath(t.Context(), path, scanInfo, c, r, make(chan matchResult, 1), &sync.Once{}, logger); err != nil {
		t.Fatalf("processPath: %v", err)
	}

	fr, ok := r.Files.Load(archiveEntryKey(path, "/marker.sh", nil))
	if !ok || len(fr.Behaviors) != 1 {
		t.Fatalf("fixture precondition: got report %+v, want one with one behavior", fr)
	}
	// A report with a single behavior is rendered.
	if got := len(renderer.rendered()); got != 1 {
		t.Errorf("reports rendered: got = %d, want = 1", got)
	}
	// The archive's extraction directory is gone before its reports are
	// rendered.
	if len(leftovers) != 0 {
		t.Errorf("temporary directory while rendering: got = %q, want empty", leftovers)
	}
}

func TestRunQueueArchiveTroubles(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)

	tests := []struct {
		name    string
		corrupt bool   // write the archive with content that does not extract, beside a script; otherwise it is missing
		wantErr string // text the error names; empty for no error
	}{
		{name: "an archive that fails to extract ends the scan before later files", corrupt: true, wantErr: "bad.tar.gz"},
		{name: "an archive gone since the walk is skipped"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			bad := filepath.Join(dir, "bad.tar.gz")
			paths := []string{bad}
			if tt.corrupt {
				// Larger than the script, so it is examined first.
				scanTestWriteFile(t, bad, queueTestCorruptGzip(4096))
				paths = append(paths, scanTestWriteFile(t, filepath.Join(dir, "locale.sh"), []byte(scanTestLocaleScript)))
			}

			logger, _ := scanTestLogger()
			r := initializeReport(nil)
			c := malcontent.Config{Concurrency: 1, ExitExtraction: tt.corrupt, Rules: yrs, RuleFS: rfs}
			err := runQueue(t.Context(), walkedFiles(paths), 1, scanPathInfo{originalPath: dir, effectivePath: dir}, c, r, make(chan matchResult, 1), &sync.Once{}, logger)
			if tt.wantErr == "" && err != nil {
				t.Errorf("runQueue: got = %v, want = nil", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("runQueue: got = %v, want an error naming %s", err, tt.wantErr)
			}
			if got := r.Files.Size(); got != 0 {
				t.Errorf("reports: got = %d (%q), want = 0", got, scanTestKeys(r.Files))
			}
		})
	}
}
