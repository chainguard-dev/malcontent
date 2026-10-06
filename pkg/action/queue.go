// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"cmp"
	"container/heap"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/minio/sha256-simd"
	"github.com/puzpuzpuz/xsync/v4"
)

// walkedFile is a file found by walking a scan path, with its size.
type walkedFile struct {
	path string
	size int64
}

// walkedFiles pairs each path with its size, which orders the queue. A path
// that cannot be examined sorts last; scanning reports its error.
func walkedFiles(paths []string) []walkedFile {
	files := make([]walkedFile, len(paths))
	for i, p := range paths {
		files[i].path = p
		if fi, err := os.Lstat(p); err == nil {
			files[i].size = fi.Size()
		}
	}
	return files
}

// task is one unit of scan work: a file found by walking a scan path, or a
// file inside an archive being scanned.
type task struct {
	path  string
	size  int64
	arc   *archiveScan  // nil for a walked file
	entry treeEntry     // archive files only
	group *extractGroup // set for the extraction of nested archives
}

// treeEntry places a file in its archive's tree. A nil batch marks a file
// that nested extraction left in place, which is scanned without checking it
// for a nested archive again.
type treeEntry struct {
	rel   string
	batch *treeBatch
	idx   int
}

// treeBatch is the files one extraction produced. Its nested archives are
// extracted once every file in it has been examined. A nested archive is
// extracted into a new directory beside it, named after the entries that
// directory already holds, so the archives that share a directory are
// extracted one at a time and in order, as ExtractArchiveToTempDir does, and
// get the same names. Archives in different directories, and different
// batches, proceed concurrently.
type treeBatch struct {
	files   []archive.TreeFile
	found   []*foundArchive // index-aligned with files; nil when not an archive
	pending atomic.Int64
	depth   int
	lineage archive.Lineage
	// origin is the file of the first extraction that this batch descends
	// from, which errors name; it is "" for the first extraction itself.
	origin string
}

// extractGroup is the nested archives of a batch that share a directory, by
// index into the batch's files, in order.
type extractGroup struct {
	batch *treeBatch
	files []int
}

// foundArchive is a nested archive found in a batch, with its content digest.
type foundArchive struct {
	n      archive.Nested
	digest [sha256.Size]byte
}

// archiveScan is one scanned archive: its extraction tree and the reports of
// the files in it, keyed by their path within it.
type archiveScan struct {
	path        string
	displayPath string
	tree        *archive.Tree
	// tmpRoot is the tree's directory with symlinks resolved, which scanned
	// paths, and so the reports' paths, are below.
	tmpRoot   string
	frs       *xsync.Map[string, *malcontent.FileReport]
	fileCount atomic.Int64
	// pending counts queued tasks and in-progress work; the archive is
	// complete when it reaches zero.
	pending atomic.Int64

	mu  sync.Mutex
	err error
}

// fail records the archive's first error.
func (a *archiveScan) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err == nil {
		a.err = err
	}
}

// failed returns the archive's first error.
func (a *archiveScan) failed() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// taskHeap orders tasks largest first, so that the longest work starts
// earliest and the scan does not end waiting on one large file.
type taskHeap []task

func (h taskHeap) Len() int { return len(h) }
func (h taskHeap) Less(i, j int) bool {
	if h[i].size != h[j].size {
		return h[i].size > h[j].size
	}
	return h[i].path < h[j].path
}
func (h taskHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *taskHeap) Push(x any)   { *h = append(*h, x.(task)) } //nolint:forcetypeassert // only tasks are pushed
func (h *taskHeap) Pop() any {
	old := *h
	n := len(old)
	t := old[n-1]
	old[n-1] = task{}
	*h = old[:n-1]
	return t
}

// scanQueue runs the files of one scan path on a fixed set of workers. Files
// inside archives being scanned come before further walked files, which keeps
// the number of extracted archives on disk bounded; within each group the
// largest file comes first.
type scanQueue struct {
	ctx       context.Context
	cancel    context.CancelFunc
	c         malcontent.Config
	scanInfo  scanPathInfo
	r         *malcontent.Report
	matchChan chan matchResult
	matchOnce *sync.Once
	logger    *clog.Logger

	mu      sync.Mutex
	wake    *sync.Cond
	walked  []walkedFile
	next    int
	tasks   taskHeap
	busy    int
	stopped bool
	err     error
	open    map[*archiveScan]struct{}
}

// runQueue scans files with up to workers concurrent workers and returns the
// first error that ends the scan.
func runQueue(ctx context.Context, files []walkedFile, workers int, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	slices.SortStableFunc(files, func(a, b walkedFile) int {
		return cmp.Compare(b.size, a.size)
	})

	qCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	q := &scanQueue{
		ctx:       qCtx,
		cancel:    cancel,
		c:         c,
		scanInfo:  scanInfo,
		r:         r,
		matchChan: matchChan,
		matchOnce: matchOnce,
		logger:    logger,
		walked:    files,
		open:      map[*archiveScan]struct{}{},
	}
	q.wake = sync.NewCond(&q.mu)

	stop := context.AfterFunc(qCtx, q.stop)
	defer stop()

	var wg sync.WaitGroup
	for range workers {
		wg.Go(q.work)
	}
	wg.Wait()

	// Archives a failure or cancellation left unfinished are removed here.
	for a := range q.open {
		q.removeTree(a)
	}
	return q.err
}

// work runs tasks until the queue is drained or stopped.
func (q *scanQueue) work() {
	for {
		t, ok := q.take()
		if !ok {
			return
		}
		q.run(t)
		q.mu.Lock()
		q.busy--
		if q.busy == 0 {
			q.wake.Broadcast()
		}
		q.mu.Unlock()
	}
}

// take returns the next task, waiting while other workers may still add
// some, and false once there is no more work or the queue stopped.
func (q *scanQueue) take() (task, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		switch {
		case q.stopped:
			return task{}, false
		case len(q.tasks) > 0:
			q.busy++
			return heap.Pop(&q.tasks).(task), true //nolint:forcetypeassert // only tasks are pushed
		case q.next < len(q.walked):
			w := q.walked[q.next]
			q.walked[q.next] = walkedFile{}
			q.next++
			q.busy++
			return task{path: w.path, size: w.size}, true
		case q.busy == 0:
			q.stopped = true
			q.wake.Broadcast()
			return task{}, false
		}
		q.wake.Wait()
	}
}

// push queues tasks.
func (q *scanQueue) push(ts ...task) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, t := range ts {
		heap.Push(&q.tasks, t)
	}
	q.wake.Broadcast()
}

// stop ends the queue: workers finish their current task and take no more.
func (q *scanQueue) stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stopped = true
	q.wake.Broadcast()
}

// fail records the error that ends the scan, if it is the first, and stops
// the queue.
func (q *scanQueue) fail(err error) {
	q.mu.Lock()
	if q.err == nil {
		q.err = err
	}
	q.mu.Unlock()
	q.cancel()
}

func (q *scanQueue) run(t task) {
	if t.group != nil {
		q.runGroup(t.arc, t.group)
		return
	}
	if t.arc != nil {
		q.runEntry(t)
		return
	}
	if err := q.runWalked(t.path); err != nil {
		q.fail(err)
	}
}

// runWalked processes a file found by the walk, as processPath does, except
// that archives are extracted into the queue.
func (q *scanQueue) runWalked(path string) error {
	ctx := q.ctx
	if ctx.Err() != nil {
		return nil
	}

	if _, ok := programkind.ArchiveMap[programkind.GetExt(path)]; ok {
		return q.openArchive(path)
	}

	fi, err := os.Stat(path)
	if err != nil {
		return handleSingleFile(ctx, path, q.scanInfo, q.c, q.r, q.matchChan, q.matchOnce, q.logger)
	}
	s := sniffFile(ctx, path, fi)
	defer s.close()
	if programkind.IsSupportedArchiveKind(path, s.kind) {
		s.close()
		return q.openArchive(path)
	}
	return handleSniffedFile(ctx, path, s, q.scanInfo, q.c, q.r, q.matchChan, q.matchOnce, q.logger)
}

// openArchive extracts the archive at path and queues the files extraction
// produced.
func (q *scanQueue) openArchive(path string) error {
	// Reports name an archive inside an OCI image by the image and its path
	// within it rather than by the temporary extraction path.
	displayPath := path
	if q.c.OCI {
		displayPath = fmt.Sprintf("%s ∴ %s", q.scanInfo.imageURI, CleanPath(path, q.scanInfo.ociExtractPath))
	}

	tree, err := archive.OpenTree(q.ctx, q.c, path)
	if err != nil {
		return q.archiveError(path, fmt.Errorf("extract to temp: %w", err))
	}

	a := &archiveScan{
		path:        path,
		displayPath: displayPath,
		tree:        tree,
		tmpRoot:     resolveDir(tree.Dir()),
		frs:         xsync.NewMap[string, *malcontent.FileReport](),
	}
	q.mu.Lock()
	q.open[a] = struct{}{}
	q.mu.Unlock()

	// Hold the archive open while its first files are queued.
	a.pending.Add(1)
	files, err := tree.Files(tree.Dir())
	if err != nil {
		a.fail(fmt.Errorf("extract to temp: failed to walk directory: %w", err))
	} else {
		q.queueBatch(a, &treeBatch{files: files, depth: 1, lineage: tree.Root()})
	}
	q.release(a)
	return nil
}

// archiveError reports an archive that could not be processed. Like the rest
// of a scan, a failed archive is logged and skipped, unless extraction errors
// end the scan.
func (q *scanQueue) archiveError(path string, err error) error {
	q.logger.Errorf("unable to process %s: %v", path, err)
	if q.c.ExitExtraction {
		return err
	}
	return nil
}

// queueBatch queues the files of b, a batch of a's tree.
func (q *scanQueue) queueBatch(a *archiveScan, b *treeBatch) {
	if len(b.files) == 0 {
		return
	}
	b.found = make([]*foundArchive, len(b.files))
	b.pending.Store(int64(len(b.files)))
	a.pending.Add(int64(len(b.files)))
	ts := make([]task, len(b.files))
	for i, f := range b.files {
		ts[i] = task{
			path:  filepath.Join(a.tmpRoot, f.Rel),
			size:  f.Size,
			arc:   a,
			entry: treeEntry{rel: f.Rel, batch: b, idx: i},
		}
	}
	q.push(ts...)
}

// release ends one unit of a's pending work, completing a after the last.
func (q *scanQueue) release(a *archiveScan) {
	if a.pending.Add(-1) == 0 {
		q.completeArchive(a)
	}
}

// runEntry examines one file of an archive: a nested archive is recorded for
// its batch to extract, and any other file is scanned, since nothing will
// replace it.
func (q *scanQueue) runEntry(t task) {
	a, e := t.arc, t.entry
	defer q.release(a)
	if e.batch != nil {
		defer q.entryDone(a, e.batch)
	}
	if q.ctx.Err() != nil || a.failed() != nil {
		return
	}

	fi, err := os.Stat(t.path)
	if err != nil {
		a.fail(err)
		return
	}
	s := sniffFile(q.ctx, t.path, fi)
	defer s.close()
	// A skipped file stays until the archive is complete: a nested archive
	// beside it is named after the entries its directory holds.
	s.keepSkipped = true

	// An empty file holds no archive: sniffing it reports no error, and Nested
	// declines it.
	if e.batch != nil && !a.tree.Extracted(e.rel) {
		if s.err != nil {
			a.fail(q.nestedError(e.batch, e.rel, fmt.Errorf("failed to determine file type: %w", s.err)))
			return
		}
		if n, ok := a.tree.Nested(e.rel, fi.Size(), s.kind); ok {
			e.batch.found[e.idx] = &foundArchive{n: n, digest: sha256.Sum256(s.content.Bytes())}
			return
		}
	}

	// Files below a .git directory take part in nested extraction but are
	// never scanned, as the walk of a scan path skips them.
	if strings.Contains(t.path, "/.git/") {
		return
	}

	fr, err := processFile(q.ctx, q.c, q.c.RuleFS, t.path, s, a.displayPath, a.tmpRoot, q.logger, &a.fileCount)
	if err != nil {
		a.fail(err)
		return
	}
	if fr != nil {
		a.frs.Store(strings.TrimPrefix(t.path, a.tmpRoot), fr)
	}
}

// entryDone marks one file of b examined. After the last, it queues the
// extraction of b's nested archives, a task for each directory holding some.
func (q *scanQueue) entryDone(a *archiveScan, b *treeBatch) {
	if b.pending.Add(-1) != 0 {
		return
	}
	byDir := map[string]int{}
	var ts []task
	for i, found := range b.found {
		if found == nil {
			continue
		}
		f := b.files[i]
		dir := filepath.Dir(f.Rel)
		g, ok := byDir[dir]
		if !ok {
			g = len(ts)
			byDir[dir] = g
			ts = append(ts, task{path: filepath.Join(a.tmpRoot, f.Rel), arc: a, group: &extractGroup{batch: b}})
		}
		ts[g].size += f.Size
		ts[g].group.files = append(ts[g].group.files, i)
	}
	if len(ts) == 0 {
		return
	}
	a.pending.Add(int64(len(ts)))
	q.push(ts...)
}

// runGroup extracts the nested archives of g in order, stopping at the first
// that fails, and queues what each extraction produced.
func (q *scanQueue) runGroup(a *archiveScan, g *extractGroup) {
	defer q.release(a)
	b := g.batch
	for _, i := range g.files {
		if q.ctx.Err() != nil || a.failed() != nil {
			return
		}
		if err := q.extractFound(a, b, i); err != nil {
			a.fail(err)
			return
		}
	}
}

// extractFound extracts the nested archive at index i of b and queues what
// extraction produced, and the archive itself when it stays in the tree.
func (q *scanQueue) extractFound(a *archiveScan, b *treeBatch, i int) error {
	rel := b.files[i].Rel
	found := b.found[i]
	dir, inner, kept, err := a.tree.ExtractNested(q.ctx, found.n, b.depth, b.lineage, found.digest)
	if err != nil {
		return q.nestedError(b, rel, err)
	}
	if kept {
		// The archive stays in the tree and is scanned as a file.
		a.pending.Add(1)
		q.push(task{path: filepath.Join(a.tmpRoot, rel), size: b.files[i].Size, arc: a, entry: treeEntry{rel: rel}})
	}
	if dir == "" {
		return nil
	}
	files, err := a.tree.Files(dir)
	if err != nil {
		return fmt.Errorf("extract to temp: failed to walk directory: failed to read directory after extraction: %w", err)
	}
	origin := b.origin
	if origin == "" {
		origin = rel
	}
	q.queueBatch(a, &treeBatch{files: files, depth: b.depth + 1, lineage: inner, origin: origin})
	return nil
}

// nestedError wraps err, from examining or extracting rel in batch b, as
// ExtractArchiveToTempDir reports it. The files of a batch that descends from
// origin lie beneath the directory origin was extracted into, so rel never
// equals origin.
func (q *scanQueue) nestedError(b *treeBatch, rel string, err error) error {
	if b.origin != "" {
		err = fmt.Errorf("process nested file %s: %w", rel, err)
	}
	return fmt.Errorf("extract to temp: failed to walk directory: %w", err)
}

// completeArchive records the reports of a finished archive, as
// handleArchiveFile does, and removes its tree.
func (q *scanQueue) completeArchive(a *archiveScan) {
	q.removeTree(a)

	if err := a.failed(); err != nil {
		if err := q.archiveError(a.path, err); err != nil {
			q.fail(err)
		}
		return
	}
	if q.ctx.Err() != nil {
		return
	}

	c, ctx, frs := q.c, q.ctx, a.frs
	if !c.OCI && (c.ExitFirstHit || c.ExitFirstMiss) {
		match, err := exitIfHitOrMiss(frs, a.path, c.ExitFirstHit, c.ExitFirstMiss)
		if err != nil {
			q.matchOnce.Do(func() {
				q.matchChan <- matchResult{fr: match, err: err}
			})
			q.fail(err)
			return
		}
	}

	frs.Range(func(entry string, fr *malcontent.FileReport) bool {
		if ctx.Err() != nil {
			return false
		}
		if entry == "" || fr == nil {
			return true
		}

		TrimFileReport(fr, c.RuleCategories)

		q.r.Files.Store(archiveEntryKey(a.displayPath, entry, c.TrimPrefixes), fr)
		if c.Renderer != nil && q.r.Diff == nil && fr.RiskScore >= c.MinFileRisk && len(fr.Behaviors) > 0 {
			if err := c.Renderer.File(ctx, fr); err != nil {
				q.logger.Errorf("render error: %v", err)
			}
		}
		return true
	})
}

// removeTree removes a's extraction directory once.
func (q *scanQueue) removeTree(a *archiveScan) {
	q.mu.Lock()
	_, ok := q.open[a]
	delete(q.open, a)
	q.mu.Unlock()
	if !ok {
		return
	}
	if err := a.tree.Close(); err != nil {
		q.logger.Errorf("remove %s: %v", a.tree.Dir(), err)
	}
}
