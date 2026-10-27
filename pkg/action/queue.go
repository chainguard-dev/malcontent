// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"cmp"
	"container/heap"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/puzpuzpuz/xsync/v4"
)

// walkedFile is a file found by walking a scan path, with its size.
type walkedFile struct {
	path    string
	name    string // path beneath the walk root
	size    int64
	regular bool // a regular file when walked
}

// walkedFiles pairs each path, found by walking beneath w, with its name
// there and its size, which orders the queue. A path that cannot be examined
// sorts last; scanning reports its error.
func walkedFiles(w *walkRoot, paths []string) []walkedFile {
	files := make([]walkedFile, len(paths))
	for i, p := range paths {
		files[i].path = p
		name, err := w.name(p)
		if err != nil {
			continue
		}
		files[i].name = name
		if fi, err := w.root.Lstat(name); err == nil {
			files[i].size = fi.Size()
			files[i].regular = fi.Mode().IsRegular()
		}
	}
	return files
}

// scanTarget is one scan path of a scan: a tree whose files a walk finds, or
// a file of a running process, read through /proc.
type scanTarget struct {
	info scanPathInfo
	proc *procTarget
	// walk reaches the files the walk finds beneath start. A walk root the
	// queue opens is closed once the walk and every file it found are done.
	walk  *walkRoot
	start string
	owned bool
	users atomic.Int64
}

// label names the target as the scan announces it.
func (tg *scanTarget) label() string {
	if tg.info.key != "" {
		return tg.info.key
	}
	return tg.info.originalPath
}

// release ends one use of the target's walk root, closing a root the queue
// opened after the last.
func (tg *scanTarget) release() {
	if tg.users.Add(-1) == 0 && tg.owned {
		tg.walk.close()
	}
}

// task is one unit of scan work: a file found by walking a scan path, or a
// file inside an archive being scanned.
type task struct {
	path    string
	name    string // a walked file's path beneath the walk root
	size    int64
	regular bool          // a walked file that was regular when walked
	target  *scanTarget   // the scan path of a walked file
	arc     *archiveScan  // nil for a walked file
	entry   treeEntry     // archive files only
	group   *extractGroup // set for the extraction of nested archives
}

// walkedTask returns the task of f, a file the walk of tg found.
func walkedTask(tg *scanTarget, f walkedFile) task {
	return task{path: f.path, name: f.name, size: f.size, regular: f.regular, target: tg}
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
	// paths, and so the reports' paths, are below; root reaches the files
	// beneath it.
	tmpRoot string
	root    *os.Root
	dirs    *file.DirRoots
	frs     *xsync.Map[string, *malcontent.FileReport]
	// pending counts queued tasks and in-progress work; the archive is
	// complete when it reaches zero.
	pending atomic.Int64

	mu  sync.Mutex
	err error
}

// fail records the archive's first error, which ends its scan and, with
// extraction errors ending the scan, the scan.
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

// walkStartBatch is how many walked files wait before workers take them
// while walks go on. Scan paths holding fewer files are scanned largest file
// first, as a whole; larger ones stream, largest first among the files
// waiting. It is a variable so that tests can observe streaming.
var walkStartBatch = 4096

// walkBacklog bounds the walked files waiting to be scanned. Walks pause
// while it is reached, so that a walk's memory does not grow with its tree.
const walkBacklog = 1 << 16

// scanQueue runs the files of a scan's paths on a fixed set of workers while
// walks of the paths add files. Files inside archives being scanned come
// before walked files, which keeps the number of extracted archives on disk
// bounded; within each group the largest file comes first.
type scanQueue struct {
	ctx       context.Context
	cancel    context.CancelFunc
	c         malcontent.Config
	r         *malcontent.Report
	matchChan chan matchResult
	matchOnce *sync.Once
	logger    *clog.Logger

	// slots, when set, are shared with other scans running at the same time;
	// a worker holds one while it runs a task.
	slots chan struct{}
	// fileCount counts the files scanned, which --max-files bounds.
	fileCount atomic.Int64

	mu sync.Mutex
	// wake signals workers waiting for tasks; room signals walks waiting for
	// room in walked.
	wake      *sync.Cond
	room      *sync.Cond
	walked    taskHeap
	walking   int  // walks still adding files
	streaming bool // workers take walked files while walks go on
	tasks     taskHeap
	busy      int
	stopped   bool
	err       error
	open      map[*archiveScan]struct{}
}

// newScanQueue returns a queue that scans into r under ctx.
func newScanQueue(ctx context.Context, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) *scanQueue {
	qCtx, cancel := context.WithCancel(ctx)
	q := &scanQueue{
		ctx:       qCtx,
		cancel:    cancel,
		c:         c,
		r:         r,
		matchChan: matchChan,
		matchOnce: matchOnce,
		logger:    logger,
		slots:     workerSlotsFrom(ctx),
		open:      map[*archiveScan]struct{}{},
	}
	q.wake = sync.NewCond(&q.mu)
	q.room = sync.NewCond(&q.mu)
	return q
}

// runQueue scans files, found beneath w by walking the scan path scanInfo
// describes, with up to workers concurrent workers and returns the first
// error that ends the scan. The caller closes w.
func runQueue(ctx context.Context, w *walkRoot, files []walkedFile, workers int, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	q := newScanQueue(ctx, c, r, matchChan, matchOnce, logger)
	defer q.cancel()
	tg := &scanTarget{info: scanInfo, walk: w}
	for _, f := range files {
		heap.Push(&q.walked, walkedTask(tg, f))
	}
	return q.run(workers, nil)
}

// scanTargets scans the files of targets with up to workers concurrent
// workers, walking the targets, one after another, while workers scan, and
// returns the first error that ends the scan.
func scanTargets(ctx context.Context, targets []*scanTarget, workers int, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	q := newScanQueue(ctx, c, r, matchChan, matchOnce, logger)
	defer q.cancel()
	q.walking = 1
	return q.run(workers, func() { q.walkTargets(targets) })
}

// run runs walk, when set, and workers until the queue is drained or stopped,
// and returns the first error that ends the scan.
func (q *scanQueue) run(workers int, walk func()) error {
	stop := context.AfterFunc(q.ctx, q.stop)
	defer stop()

	var wg sync.WaitGroup
	if walk != nil {
		wg.Go(walk)
	}
	for range workers {
		wg.Go(q.work)
	}
	wg.Wait()

	// Walked files a failure or cancellation left unscanned, and archives it
	// left unfinished, let go of what they hold here.
	for _, t := range q.walked {
		t.target.release()
	}
	q.walked = nil
	for a := range q.open {
		q.removeTree(a)
	}
	return q.err
}

// walkTargets walks each target in turn, adding the files it finds.
func (q *scanQueue) walkTargets(targets []*scanTarget) {
	defer q.walkDone()
	for _, tg := range targets {
		if q.ctx.Err() != nil {
			return
		}
		q.walkTarget(tg)
	}
}

// walkTarget adds the files of tg: a process's file, or the files a walk of
// its scan path finds.
func (q *scanQueue) walkTarget(tg *scanTarget) {
	if tg.proc != nil {
		q.addWalked(task{path: tg.proc.path, target: tg})
		return
	}
	w, start, err := openScanPath(q.ctx, tg.info.effectivePath)
	if err != nil {
		q.fail(err)
		return
	}
	if w == nil {
		return
	}
	tg.walk, tg.start, tg.owned = w, start, true
	// The walk holds the root until it ends, and each file it finds until
	// that file is done.
	tg.users.Store(1)
	defer tg.release()
	walkInto(q.ctx, w, start, func(f walkedFile) {
		tg.users.Add(1)
		if !q.addWalked(walkedTask(tg, f)) {
			tg.release()
		}
	})
}

// addWalked queues t, a walked file, waiting while walkBacklog files wait.
// It reports false once the queue stopped.
func (q *scanQueue) addWalked(t task) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.walked) >= walkBacklog && !q.stopped {
		q.room.Wait()
	}
	if q.stopped {
		return false
	}
	heap.Push(&q.walked, t)
	switch {
	case q.streaming:
		q.wake.Signal()
	case len(q.walked) >= walkStartBatch:
		q.streaming = true
		q.wake.Broadcast()
	}
	return true
}

// walkDone marks one walk finished.
func (q *scanQueue) walkDone() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.walking--
	q.wake.Broadcast()
}

// work runs tasks until the queue is drained or stopped.
func (q *scanQueue) work() {
	for {
		t, ok := q.take()
		if !ok {
			return
		}
		release := q.acquireSlot()
		q.runTask(t)
		release()
		q.mu.Lock()
		q.busy--
		if q.busy == 0 {
			q.wake.Broadcast()
		}
		q.mu.Unlock()
	}
}

type workerSlotsCtxKey struct{}

// withWorkerSlots returns ctx carrying n worker slots. The scans started under
// it together run at most n tasks at once, as one scan with n workers would.
func withWorkerSlots(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, workerSlotsCtxKey{}, make(chan struct{}, n))
}

// workerSlotsFrom returns the worker slots ctx carries, or nil.
func workerSlotsFrom(ctx context.Context) chan struct{} {
	slots, _ := ctx.Value(workerSlotsCtxKey{}).(chan struct{})
	return slots
}

// acquireSlot waits for a shared worker slot, when the queue has them, and
// returns the function that gives it back. Once the scan ends, the task runs
// without one: it returns early, and still settles its archive's accounting.
func (q *scanQueue) acquireSlot() func() {
	if q.slots == nil {
		return func() {}
	}
	select {
	case q.slots <- struct{}{}:
		return func() { <-q.slots }
	case <-q.ctx.Done():
		return func() {}
	}
}

// take returns the next task, waiting while walks or other workers may still
// add some, and false once there is no more work or the queue stopped.
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
		case len(q.walked) > 0 && (q.streaming || q.walking == 0):
			q.busy++
			q.room.Signal()
			return heap.Pop(&q.walked).(task), true //nolint:forcetypeassert // only tasks are pushed
		case q.busy == 0 && q.walking == 0:
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

// stop ends the queue: workers finish their current task and take no more,
// and walks add no more files.
func (q *scanQueue) stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stopped = true
	q.wake.Broadcast()
	q.room.Broadcast()
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

// runTask runs t.
func (q *scanQueue) runTask(t task) {
	if t.group != nil {
		q.runGroup(t.arc, t.group)
		return
	}
	if t.arc != nil {
		q.runEntry(t)
		return
	}
	defer t.target.release()
	if err := q.runWalked(t); err != nil {
		q.fail(err)
	}
}

// runWalked processes t, a file found by the walk of a scan path: an archive
// is extracted into the queue, and any other file is scanned. A file that
// cannot be scanned is reported as skipped; the error returned ends the scan.
func (q *scanQueue) runWalked(t task) error {
	if q.ctx.Err() != nil {
		return nil
	}
	if t.target.proc != nil {
		return q.runProcess(t)
	}
	if hasArchiveExt(t.path) && q.regularNow(t) {
		return q.openArchive(t)
	}
	s, err := q.sniffWalked(t)
	if err != nil {
		q.fileError(t, err)
		return nil
	}
	defer s.close()
	if s.fi.Mode().IsRegular() && programkind.IsSupportedArchiveKind(t.path, s.kind) {
		s.close()
		return q.openArchive(t)
	}
	return q.handle(t, s)
}

// hasArchiveExt reports whether path is named like an archive.
func hasArchiveExt(path string) bool {
	_, ok := programkind.ArchiveMap[programkind.GetExt(path)]
	return ok
}

// regularNow reports whether the walked file t is a regular file now. It
// opens the file without blocking, so that a FIFO named like an archive, or
// put in place of one, cannot stall the scan in open(2).
func (q *scanQueue) regularNow(t task) bool {
	if !t.regular {
		return false
	}
	r, name, release, err := t.target.walk.dirs.Parent(t.name)
	if err != nil {
		return false
	}
	defer release()
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	fi, err := f.Stat()
	return err == nil && fi.Mode().IsRegular()
}

// sniffWalked reads and detects the walked file t through the walk root's
// directories. Walked files belong to the user, so their contents are read
// rather than mapped.
func (q *scanQueue) sniffWalked(t task) (*sniffed, error) {
	r, name, release, err := t.target.walk.dirs.Parent(t.name)
	if err != nil {
		return nil, err
	}
	s, err := sniffEntry(q.ctx, r, name, t.path, t.regular, false)
	if err != nil {
		release()
		return nil, err
	}
	s.release = release
	return s, nil
}

// handle scans t, a walked file that s holds, and records its report.
func (q *scanQueue) handle(t task, s *sniffed) error {
	return handleSniffedFile(q.ctx, t.path, s, t.target.info, q.c, q.r, q.matchChan, q.matchOnce, q.logger, &q.fileCount)
}

// scanPlain scans the walked file t as a file, without extracting it.
func (q *scanQueue) scanPlain(t task) error {
	s, err := q.sniffWalked(t)
	if err != nil {
		q.fileError(t, err)
		return nil
	}
	defer s.close()
	return q.handle(t, s)
}

// fileError records that the walked file t could not be scanned because of
// err, as a skipped report, so that the scan goes on. An error from the end
// of the scan is not recorded.
func (q *scanQueue) fileError(t task, err error) {
	if q.ctx.Err() != nil {
		return
	}
	key := fileKey(t.path, t.target.info, q.c)
	q.logger.Errorf("unable to scan %s: %v", key, err)
	q.r.Files.Store(key, &malcontent.FileReport{Path: key, Skipped: skipReason(err)})
}

// runProcess scans t, the file of a running process, read through /proc as
// the process sees it. An archive, such as a UPX-packed executable, is
// extracted from a copy.
func (q *scanQueue) runProcess(t task) error {
	p := t.target.proc
	f, err := p.open()
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ESRCH):
		// The process exited.
		q.logger.Debugf("skipping %s: %v", p.key, err)
		return nil
	case err != nil:
		q.fileError(t, err)
		return nil
	}
	s, ok := sniffFrom(q.ctx, f, p.path, false)
	_ = f.Close()
	if !ok {
		q.fileError(t, errors.New("open: not a regular file"))
		return nil
	}
	defer s.close()
	if programkind.IsSupportedArchiveKind(p.path, s.kind) {
		return q.extract(t, p.key, func() (*archive.Tree, error) { return q.extractCopy(s, p) }, func() error { return q.handle(t, s) })
	}
	return q.handle(t, s)
}

// extractCopy writes s, the contents of p, a process's file holding an
// archive, to a new temporary directory and extracts it from there: archives
// are extracted from a path, and no path of ours may reach the process's
// file. The copy is removed once extracted.
func (q *scanQueue) extractCopy(s *sniffed, p *procTarget) (*archive.Tree, error) {
	if s.content == nil {
		return nil, cmp.Or(s.err, errors.New("no contents"))
	}
	dir, err := os.MkdirTemp("", "malcontent-process")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.RemoveAllIn(filepath.Dir(dir), filepath.Base(dir)); err != nil {
			q.logger.Errorf("remove %s: %v", dir, err)
		}
	}()
	name := filepath.Base(p.path)
	if !filepath.IsLocal(name) {
		name = "exe"
	}
	if err := file.WriteFileIn(dir, name, s.content.Bytes(), 0o600); err != nil {
		return nil, err
	}
	return archive.OpenTree(q.ctx, q.c, filepath.Join(dir, name))
}

// openArchive extracts t, a walked archive, and queues the files extraction
// produced, scanning t as a file when extraction fails or produces nothing.
func (q *scanQueue) openArchive(t task) error {
	// Reports name an archive inside an OCI image by the image and its path
	// within it rather than by the temporary extraction path.
	displayPath := t.path
	if q.c.OCI {
		displayPath = fmt.Sprintf("%s ∴ %s", t.target.info.imageURI, CleanPath(t.path, t.target.info.ociExtractPath))
	}
	return q.extract(t, displayPath, func() (*archive.Tree, error) { return q.openTree(t) }, func() error { return q.scanPlain(t) })
}

// extract extracts t, an archive, with open and queues the files extraction
// produced; reports name the archive displayPath. When extraction fails or
// produces nothing, plain scans t as a file, so that nothing it holds goes
// unscanned, unless extraction errors end the scan.
func (q *scanQueue) extract(t task, displayPath string, open func() (*archive.Tree, error), plain func() error) error {
	path := t.path
	tree, err := open()
	if err != nil {
		return q.extractionFailed(path, fmt.Errorf("extract to temp: %w", err), plain)
	}
	files, err := tree.Files(tree.Dir())
	if err != nil {
		q.closeTree(tree)
		return q.extractionFailed(path, fmt.Errorf("extract to temp: failed to walk directory: %w", err), plain)
	}
	if len(files) == 0 {
		q.closeTree(tree)
		q.logger.Debugf("%s holds no files, scanning it as a file", path)
		return plain()
	}
	tmpRoot := resolveDir(tree.Dir())
	root, err := os.OpenRoot(tmpRoot)
	if err != nil {
		q.closeTree(tree)
		return q.extractionFailed(path, fmt.Errorf("extract to temp: %w", err), plain)
	}

	a := &archiveScan{
		path:        path,
		displayPath: displayPath,
		tree:        tree,
		tmpRoot:     tmpRoot,
		root:        root,
		dirs:        file.NewDirRoots(root, maxIdleDirRoots),
		frs:         xsync.NewMap[string, *malcontent.FileReport](),
	}
	q.mu.Lock()
	q.open[a] = struct{}{}
	q.mu.Unlock()

	// Hold the archive open while its first files are queued.
	a.pending.Add(1)
	q.queueBatch(a, &treeBatch{files: files, depth: 1, lineage: tree.Root()})
	q.release(a)
	return nil
}

// extractionFailed handles err, the failure to extract the archive at path.
// A file no extractor handles is no archive, so it is scanned as a file with
// plain. Any other failure is logged and returned when extraction errors end
// the scan; otherwise the archive is scanned as a file too.
func (q *scanQueue) extractionFailed(path string, err error, plain func() error) error {
	if errors.Is(err, archive.ErrUnsupportedArchive) {
		q.logger.Debugf("%s is no archive malcontent extracts, scanning it as a file: %v", path, err)
		return plain()
	}
	if q.c.ExitExtraction {
		return q.archiveError(path, err)
	}
	q.logger.Warnf("unable to extract %s, scanning it as a file: %v", path, err)
	return plain()
}

// closeTree removes an extraction tree that no archive scan holds.
func (q *scanQueue) closeTree(tree *archive.Tree) {
	if err := tree.Close(); err != nil {
		q.logger.Errorf("remove %s: %v", tree.Dir(), err)
	}
}

// openTree extracts t, a walked archive, reading it through the root on its
// directory, so that an archive at a path too long to hand the operating
// system whole is still extracted.
func (q *scanQueue) openTree(t task) (*archive.Tree, error) {
	r, base, release, err := t.target.walk.dirs.Parent(t.name)
	if err != nil {
		return archive.OpenTree(q.ctx, q.c, t.path)
	}
	defer release()
	return archive.OpenTreeIn(q.ctx, q.c, r, base, t.path)
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
// replace it. A file that cannot be examined is reported as skipped, and the
// rest of the archive is still scanned.
func (q *scanQueue) runEntry(t task) {
	a, e := t.arc, t.entry
	defer q.release(a)
	if e.batch != nil {
		defer q.entryDone(a, e.batch)
	}
	if q.ctx.Err() != nil || a.failed() != nil {
		return
	}
	// The object stores of git repositories are neither extracted nor
	// scanned, as walks of scan paths pass over them.
	if inGitObjects(e.rel) {
		return
	}

	r, name, release, err := a.dirs.Parent(e.rel)
	if err != nil {
		q.entryError(a, t, err)
		return
	}
	// The tree holds only regular files, which malcontent extracted, so their
	// contents may be mapped.
	s, err := sniffEntry(q.ctx, r, name, t.path, true, true)
	if err != nil {
		release()
		q.entryError(a, t, err)
		return
	}
	s.release = release
	defer s.close()
	// A skipped file stays until the archive is complete: a nested archive
	// beside it is named after the entries its directory holds.
	s.keepSkipped = true

	// An empty file holds no archive: sniffing it reports no error, and Nested
	// declines it.
	if e.batch != nil && !a.tree.Extracted(e.rel) {
		if s.err != nil {
			err := fmt.Errorf("failed to determine file type: %w", s.err)
			if q.c.ExitExtraction {
				a.fail(q.nestedError(e.batch, e.rel, err))
				return
			}
			q.entryError(a, t, err)
			return
		}
		if n, ok := a.tree.Nested(e.rel, s.fi.Size(), s.kind); ok {
			e.batch.found[e.idx] = &foundArchive{n: n, digest: sha256.Sum256(s.content.Bytes())}
			return
		}
	}

	fr, err := processFile(q.ctx, q.c, q.c.RuleFS, t.path, s, a.displayPath, a.tmpRoot, q.logger, &q.fileCount)
	if err != nil {
		q.fail(err)
		return
	}
	if fr == nil {
		return
	}
	entry := strings.TrimPrefix(t.path, a.tmpRoot)
	TrimFileReport(fr, q.c.RuleCategories)
	if err := meetExitCriteria(fr, archiveEntryKey(a.displayPath, entry, q.c.TrimPrefixes), q.c, q.matchChan, q.matchOnce); err != nil {
		q.fail(err)
		return
	}
	a.frs.Store(entry, fr)
}

// entryError records that t, a file of archive a, could not be scanned
// because of err, as a skipped report. An error from the end of the scan is
// not recorded.
func (q *scanQueue) entryError(a *archiveScan, t task, err error) {
	if q.ctx.Err() != nil {
		return
	}
	entry := strings.TrimPrefix(t.path, a.tmpRoot)
	key := archiveEntryKey(a.displayPath, entry, q.c.TrimPrefixes)
	q.logger.Errorf("unable to scan %s: %v", key, err)
	a.frs.Store(entry, &malcontent.FileReport{Path: key, Skipped: skipReason(err)})
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

// runGroup extracts the nested archives of g in order and queues what each
// extraction produced. A failure is logged and the rest are extracted, unless
// extraction errors end the scan, which stops at the first.
func (q *scanQueue) runGroup(a *archiveScan, g *extractGroup) {
	defer q.release(a)
	b := g.batch
	for _, i := range g.files {
		if q.ctx.Err() != nil || a.failed() != nil {
			return
		}
		err := q.extractFound(a, b, i)
		switch {
		case err == nil:
		case q.c.ExitExtraction:
			a.fail(err)
			return
		default:
			q.logger.Errorf("unable to process %s: %v", a.path, err)
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
		err = fmt.Errorf("process nested file %q: %w", rel, err)
	}
	return fmt.Errorf("extract to temp: failed to walk directory: %w", err)
}

// completeArchive records the reports of a finished archive, as
// handleArchiveFile does, and removes its tree. Its files were filtered, and
// judged against the exit criteria, as they were scanned.
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

	c, ctx := q.c, q.ctx
	a.frs.Range(func(entry string, fr *malcontent.FileReport) bool {
		if ctx.Err() != nil {
			return false
		}
		if entry == "" || fr == nil {
			return true
		}

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
	a.dirs.Close()
	_ = a.root.Close()
	if err := a.tree.Close(); err != nil {
		q.logger.Errorf("remove %s: %v", a.tree.Dir(), err)
	}
}
