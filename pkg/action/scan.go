// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/puzpuzpuz/xsync/v4"

	yarax "github.com/VirusTotal/yara-x/go"
)

func interactive(c malcontent.Config) bool {
	return c.Renderer != nil && c.Renderer.Name() == "Interactive"
}

var (
	activeScannerPool   atomic.Pointer[rulesScannerPool] // activeScannerPool holds scanners for the most recently scanned rule set.
	lastRuleSet         atomic.Pointer[ruleSet]          // lastRuleSet is the rule set CachedRules returned most recently.
	ruleSets            []*ruleSet                       // ruleSets are the rule sets CachedRules compiled, oldest first; compileMu guards it.
	compileMu           sync.Mutex                       // compileMu ensures that one caller at a time compiles rules.
	ErrMatchedCondition = errors.New("matched exit criteria")
	scannerPoolMu       sync.Mutex // scannerPoolMu serializes replacing activeScannerPool.
	// errRules wraps the failure to compile the rule set, which ends a scan
	// rather than skipping one file.
	errRules = errors.New("rules")
)

// ruleSet is a rule set CachedRules compiled and the rule sources it came
// from.
type ruleSet struct {
	fss   []fs.FS
	rules *yarax.Rules
}

// maxRuleSets bounds the rule sets CachedRules keeps compiled.
const maxRuleSets = 4

// rulesScannerPool is a scanner pool built for one compiled rule set. Once
// replaced by a pool for other rules, it closes when its last borrower
// releases it.
type rulesScannerPool struct {
	rules     *yarax.Rules
	scanners  *pool.ScannerPool
	inUse     atomic.Int64
	retired   atomic.Bool
	closeOnce sync.Once
}

// acquireScannerPool returns a pool whose scanners use yrs, replacing the
// active pool when it was built for other rules. Callers must release it.
// Scanning with the active rule set takes no lock and allocates nothing.
func acquireScannerPool(yrs *yarax.Rules) *rulesScannerPool {
	for {
		p := activeScannerPool.Load()
		if p == nil || p.rules != yrs {
			p = replaceScannerPool(yrs)
		}
		p.inUse.Add(1)
		if !p.retired.Load() {
			return p
		}
		// Replaced between loading and borrowing it: retry with the new pool.
		p.release()
	}
}

// replaceScannerPool makes a pool for yrs the active pool unless another
// caller already did, and retires the pool it replaces.
func replaceScannerPool(yrs *yarax.Rules) *rulesScannerPool {
	scannerPoolMu.Lock()
	defer scannerPoolMu.Unlock()

	old := activeScannerPool.Load()
	if old != nil && old.rules == yrs {
		return old
	}
	// always create one scanner per available CPU core since the pool is used for the duration of
	// a scan which may involve concurrent scans of individual files
	p := &rulesScannerPool{
		rules:    yrs,
		scanners: pool.NewScannerPool(yrs, getMaxConcurrency(runtime.GOMAXPROCS(0))),
	}
	activeScannerPool.Store(p)
	if old != nil {
		old.retire()
	}
	return p
}

// retire marks the pool as replaced and closes it if no scan is using it.
func (p *rulesScannerPool) retire() {
	p.retired.Store(true)
	if p.inUse.Load() == 0 {
		p.closeOnce.Do(p.scanners.Close)
	}
}

// release ends one borrow and closes a retired pool after its last borrower.
func (p *rulesScannerPool) release() {
	if p.inUse.Add(-1) == 0 && p.retired.Load() {
		p.closeOnce.Do(p.scanners.Close)
	}
}

// scanSinglePath YARA scans a single path and converts it to a fileReport.
func scanSinglePath(ctx context.Context, c malcontent.Config, path string, ruleFS []fs.FS, absPath string, archiveRoot string, fileCount *atomic.Int64) (*malcontent.FileReport, error) {
	if ctx.Err() != nil {
		return &malcontent.FileReport{}, ctx.Err()
	}

	dir, name, err := file.Split(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fi, err := root.Stat(name)
	if err != nil {
		return nil, err
	}
	s := sniffFile(ctx, root, name, path, fi)
	defer s.close()
	return scanSniffed(ctx, c, path, s, ruleFS, absPath, archiveRoot, fileCount)
}

// scanSniffed YARA scans a file already read and detected by sniffFile and
// converts it to a fileReport.
func scanSniffed(ctx context.Context, c malcontent.Config, path string, s *sniffed, ruleFS []fs.FS, absPath string, archiveRoot string, fileCount *atomic.Int64) (*malcontent.FileReport, error) {
	logger := clog.FromContext(ctx)
	logger = logger.With("path", path)

	isArchive := archiveRoot != ""
	skip := func(reason string) (*malcontent.FileReport, error) {
		// Immediately remove skipped files within archives
		if isArchive && !s.keepSkipped {
			if err := s.root.RemoveAll(s.name); err != nil {
				logger.Warnf("remove skipped archive entry %s: %v", path, err)
			}
		}
		return &malcontent.FileReport{Skipped: reason, Path: path}, nil
	}

	size := s.fi.Size()
	if size == 0 {
		return skip("zero-sized file")
	}

	mime := "<unknown>"
	kind := s.kind
	if s.err != nil && !interactive(c) {
		logger.Errorf("file type failure: %s: %s", path, s.err)
	}
	if kind != nil {
		mime = kind.MIME
	}

	if !c.IncludeDataFiles && kind == nil {
		logger.Debugf("skipping %s [%s]: data file or empty", path, mime)
		return skip("data file or empty")
	}
	logger = logger.With("mime", mime)

	if fileCount != nil {
		count := fileCount.Add(1)
		if c.MaxScanFiles > 0 && count > int64(c.MaxScanFiles) {
			logger.Warnf("skipping %s: file count %d exceeds limit %d", path, count, c.MaxScanFiles)
			return skip("max file count exceeded")
		}
	}

	yrs := c.Rules
	if yrs == nil {
		var err error
		if yrs, err = CachedRules(ctx, ruleFS); err != nil {
			return nil, fmt.Errorf("%w: %w", errRules, err)
		}
	}
	// Report generation caches per-rule data for the rule set it is given.
	c.Rules = yrs

	// Sniffing leaves files it could not read unread; they are read now, so
	// that every file is scanned from its contents.
	if err := s.load(ctx); err != nil {
		logger.Debug("skipping", slog.Any("error", err))
		return nil, err
	}
	fc := s.content.Bytes()
	sum := sha256.Sum256(capContents(fc))
	matching, err := scanFile(ctx, c, s, path, archiveRoot, fc, sum)
	if err != nil {
		logger.Debug("skipping", slog.Any("error", err))
		return nil, err
	}

	// A scan without the quantity upgrade skips a file whose highest risk,
	// once overrides and ignored rules and tags apply, stays below what it
	// reports, before building the report. With the upgrade, many HIGH
	// behaviors can raise a file, so every report is built.
	risk := 0
	if c.Scan && !c.QuantityIncreasesRisk {
		risk = report.HighestMatchRiskRules(matching, kind, path, archiveRoot, c)
		if risk < max(report.HIGH, c.MinFileRisk, c.MinRisk) {
			return skip("overall risk too low for scan")
		}
	}

	fr, err := report.GenerateRules(ctx, path, matching, c, archiveRoot, capContents(fc), size, hex.EncodeToString(sum[:]), kind)
	if err != nil {
		return nil, NewFileReportError(err, path, TypeGenerateError)
	}

	// Clean up the path if scanning an archive
	var clean string
	if isArchive || c.OCI {
		if absPath, clean, err = archivePaths(fr, c, path, absPath, archiveRoot); err != nil {
			return nil, NewFileReportError(err, path, TypeGenerateError)
		}
	}

	if len(fr.Behaviors) == 0 {
		if isArchive {
			return &malcontent.FileReport{Path: fmt.Sprintf("%s ∴ %s", absPath, clean)}, nil
		}
		return &malcontent.FileReport{Path: report.DisplayPath(path, c.TrimPrefixes)}, nil
	}

	return fr, nil
}

// scanFile returns the rules that match the file s describes: the matches of
// c.Rules and, when c.Rules comes with rules set aside, of the scoped rules
// that apply to the file and the rules for its header. fc and sum are the
// file's contents and their capped digest.
func scanFile(ctx context.Context, c malcontent.Config, s *sniffed, path, archiveRoot string, fc []byte, sum [sha256.Size]byte) ([]*yarax.Rule, error) {
	// The file holds its share of the scan memory budget since its contents
	// were read.
	mrs, err := scanContent(ctx, c.Rules, fc, sum)
	if err != nil {
		return nil, err
	}
	sr := scopedFor(c.Rules)
	if sr == nil {
		return mrs.MatchingRules(), nil
	}
	// With rules divided by scope and header, the file is also scanned with
	// the scoped rules that apply to it and the rules for its header, and
	// reports read the matches of every scan.
	var sets []*yarax.Rules
	if key, indices := sr.applicable(s.kind, path, archiveRoot, c); len(indices) > 0 {
		rules, err := sr.set(ctx, key, indices)
		if err != nil {
			return nil, err
		}
		sets = append(sets, rules)
	}
	header, err := sr.forHeader(fc)
	if err != nil {
		return nil, err
	}
	if header != nil {
		sets = append(sets, header)
	}
	if len(sets) == 0 {
		return mrs.MatchingRules(), nil
	}
	others := make([]*yarax.ScanResults, 0, len(sets))
	for _, rules := range sets {
		res, err := scanContent(ctx, rules, fc, sum)
		if err != nil {
			return nil, err
		}
		others = append(others, res)
	}
	return mergeMatches(mrs, others...), nil
}

// archivePaths sets the archive root and full path of fr, the report for the
// file at path extracted under archiveRoot, and its display path when the
// file came from the archive at absPath. It returns absPath as displayed and
// path relative to archiveRoot.
func archivePaths(fr *malcontent.FileReport, c malcontent.Config, path, absPath, archiveRoot string) (string, string, error) {
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	archiveRootAbs, err := filepath.Abs(archiveRoot)
	if err != nil {
		return "", "", err
	}

	// Both display paths reuse absPath. The extracted file and the extraction
	// directory are spelled alike, so that one is relative to the other
	// however each was reached.
	absPath = report.DisplayPath(formatPath(absPath), c.TrimPrefixes)
	pathAbs = report.DisplayPath(formatPath(pathAbs), nil)
	archiveRootAbs = report.DisplayPath(formatPath(archiveRootAbs), nil)

	fr.ArchiveRoot = archiveRootAbs
	fr.FullPath = pathAbs
	clean := CleanPath(pathAbs, archiveRootAbs)

	if absPath != "" && absPath != path {
		fr.Path = fmt.Sprintf("%s ∴ %s", absPath, clean)
	}
	return absPath, clean, nil
}

// exitIfHitOrMiss applies the exit criteria to frs, the filtered reports of
// the files of scanPath, as a whole: a hit is a scanned file with behaviors
// at or above minFileRisk, and a miss is a scan path without one. It returns
// the error that ends the scan when they are met, with the first hit for a
// hit.
func exitIfHitOrMiss(frs *xsync.Map[string, *malcontent.FileReport], scanPath string, errIfHit bool, errIfMiss bool, minFileRisk int) (*malcontent.FileReport, error) {
	if frs == nil {
		return nil, nil
	}
	var scanned int
	var match *malcontent.FileReport
	frs.Range(func(_ string, fr *malcontent.FileReport) bool {
		if fr == nil || fr.Skipped != "" {
			return true
		}
		scanned++
		if match == nil && isHit(fr, minFileRisk) {
			match = fr
		}
		return true
	})
	switch {
	case scanned == 0:
		return nil, nil
	case errIfHit && match != nil:
		return match, fmt.Errorf("%s %w", scanPath, ErrMatchedCondition)
	case errIfMiss && match == nil:
		return nil, fmt.Errorf("%s %w", scanPath, ErrMatchedCondition)
	}
	return nil, nil
}

// isHit reports whether fr, a filtered report, survives --min-file-risk with
// behaviors to show.
func isHit(fr *malcontent.FileReport, minFileRisk int) bool {
	return len(fr.Behaviors) > 0 && fr.RiskScore >= minFileRisk
}

// meetExitCriteria applies the exit criteria to fr, the filtered report of
// one scanned file, which the error names as path: a hit is a file with
// behaviors at or above --min-file-risk, and a miss any other scanned file.
// A file that meets them is queued as the match, a hit with its report, and
// the error that ends the scan is returned. An OCI image is judged as a
// whole instead.
func meetExitCriteria(fr *malcontent.FileReport, path string, c malcontent.Config, matchChan chan matchResult, matchOnce *sync.Once) error {
	if c.OCI || (!c.ExitFirstHit && !c.ExitFirstMiss) || fr == nil || fr.Skipped != "" {
		return nil
	}
	var match *malcontent.FileReport
	hit := isHit(fr, c.MinFileRisk)
	switch {
	case c.ExitFirstHit && hit:
		match = fr
	case c.ExitFirstMiss && !hit:
	default:
		return nil
	}
	err := fmt.Errorf("%s %w", path, ErrMatchedCondition)
	matchOnce.Do(func() {
		matchChan <- matchResult{fr: match, err: err}
	})
	return err
}

// CachedRules returns the rules in fss, compiled once per process for each
// set of rule sources: a call with the same sources returns the same rule
// set, and a call with other sources compiles them.
func CachedRules(ctx context.Context, fss []fs.FS) (*yarax.Rules, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Scans keep directories open; making room for them while the rules
	// load keeps the descriptor table from growing during the scan.
	file.ReserveDescriptors()

	if rs := lastRuleSet.Load(); rs != nil && sameRuleSources(rs.fss, fss) {
		return rs.rules, nil
	}

	compileMu.Lock()
	defer compileMu.Unlock()
	if i := slices.IndexFunc(ruleSets, func(rs *ruleSet) bool { return sameRuleSources(rs.fss, fss) }); i >= 0 {
		lastRuleSet.Store(ruleSets[i])
		return ruleSets[i].rules, nil
	}
	// A failed or canceled compile is not cached, so the next call tries
	// again.
	yrs, err := compileRules(ctx, fss)
	if err != nil {
		return nil, err
	}
	rs := &ruleSet{fss: slices.Clone(fss), rules: yrs}
	ruleSets = append(ruleSets[max(len(ruleSets)-maxRuleSets+1, 0):], rs)
	lastRuleSet.Store(rs)
	return yrs, nil
}

// sameRuleSources reports whether a and b name the same rule sources, in the
// same order.
func sameRuleSources(a, b []fs.FS) bool {
	return slices.EqualFunc(a, b, sameFS)
}

// sameFS reports whether a and b are the same filesystem: equal values, such
// as embedded filesystems or os.DirFS directories, or the same map or
// pointer, such as one fstest.MapFS. Filesystems of other types never match,
// so their rules are compiled on every call.
func sameFS(a, b fs.FS) bool {
	ta, tb := reflect.TypeOf(a), reflect.TypeOf(b)
	switch {
	case ta != tb:
		return false
	case ta == nil:
		return true
	case ta.Comparable():
		return a == b
	}
	switch va, vb := reflect.ValueOf(a), reflect.ValueOf(b); va.Kind() {
	case reflect.Map, reflect.Pointer, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return va.Pointer() == vb.Pointer()
	case reflect.Slice:
		return va.Pointer() == vb.Pointer() && va.Len() == vb.Len()
	default:
		return false
	}
}

// compileRules compiles the rules in fss divided by scope, so that each file
// is scanned only with the scoped rules that apply to it; the universal rule
// set it returns stands for all of them. Should dividing fail, every rule is
// compiled into one set, as before.
func compileRules(ctx context.Context, fss []fs.FS) (*yarax.Rules, error) {
	split, err := compile.RecursiveSplitCached(ctx, fss)
	if err == nil {
		registerSplit(split)
		return split.Universal, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	clog.WarnContextf(ctx, "dividing rules by scope failed, compiling them together: %v", err)
	yrs, err := compile.RecursiveCached(ctx, fss)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	return yrs, nil
}

// matchResult represents the outcome of a match operation.
type matchResult struct {
	fr  *malcontent.FileReport
	err error
}

// scanPathInfo contains information about the path being scanned.
type scanPathInfo struct {
	originalPath   string
	effectivePath  string
	ociExtractPath string
	imageURI       string
	// key, when set, is the report key of the file the scan path names,
	// such as a process's executable named by its path and pid.
	key string
}

// recursiveScan recursively YARA scans the configured paths - handling archives and OCI images.
func recursiveScan(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	if ctx.Err() != nil {
		return &malcontent.Report{}, ctx.Err()
	}

	logger := clog.FromContext(ctx)
	r := initializeReport(c.IgnoreTags)
	matchChan := make(chan matchResult, 1)
	var matchOnce sync.Once
	// A diff attaches one cache for both of its scans.
	if resultCacheFrom(ctx) == nil {
		ctx = withResultCache(ctx)
	}

	// Each OCI image is pulled, scanned, and judged by the exit criteria on
	// its own.
	if c.OCI {
		for _, scanPath := range c.ScanPaths {
			if err := handleScanPath(ctx, scanPath, c, r, matchChan, &matchOnce, logger); err != nil {
				return r, err
			}
		}
		return r, nil
	}

	targets, err := resolveTargets(ctx, c.ScanPaths)
	if err != nil {
		return r, err
	}
	if c.Renderer != nil {
		for _, tg := range targets {
			c.Renderer.Scanning(ctx, tg.label())
		}
	}
	// Every scan path feeds one queue, so that many small scan paths, such
	// as the executables of running processes, are scanned concurrently.
	return r, collectPaths(ctx, scanPathInfo{}, c, r, matchChan, logger, func(dest *malcontent.Report) error {
		return scanTargets(ctx, targets, getMaxConcurrency(c.Concurrency), c, dest, matchChan, &matchOnce, logger)
	})
}

// resolveTargets returns the scan target of each scan path, checking first
// that each can be scanned: a scan path that does not exist, or cannot be
// opened, fails the scan before anything is scanned. Dangling symlinks, and
// /proc paths of processes that have exited, are left out.
func resolveTargets(ctx context.Context, paths []string) ([]*scanTarget, error) {
	targets := make([]*scanTarget, 0, len(paths))
	for _, p := range paths {
		info := scanPathInfo{originalPath: p, effectivePath: p}
		if proc, ok := procTargetFor(p); ok {
			if proc == nil {
				clog.DebugContextf(ctx, "skipping %s: the process has exited", p)
				continue
			}
			info.key = proc.key
			targets = append(targets, &scanTarget{info: info, proc: proc})
			continue
		}
		// The walk opens the scan path again once it reaches it, so that
		// many scan paths do not hold descriptors while they wait.
		w, _, err := openScanPath(ctx, p)
		if err != nil {
			return nil, err
		}
		if w == nil {
			continue
		}
		w.close()
		targets = append(targets, &scanTarget{info: info})
	}
	return targets, nil
}

func initializeReport(ignoreTags []string) *malcontent.Report {
	r := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
	}
	if len(ignoreTags) > 0 {
		r.Filter = strings.Join(ignoreTags, ",")
	}
	return r
}

// handleScanPath pulls and scans scanPath, an OCI image.
func handleScanPath(ctx context.Context, scanPath string, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if c.Renderer != nil {
		c.Renderer.Scanning(ctx, scanPath)
	}

	scanInfo, err := prepareScanPath(ctx, scanPath, c, logger)
	if err != nil {
		return fmt.Errorf("failed to prepare scan path: %w", err)
	}

	if c.OCI && scanInfo.ociExtractPath != "" {
		defer cleanupOCIPath(scanInfo.ociExtractPath, logger)
	}

	targets := []*scanTarget{{info: scanInfo}}
	return collectPaths(ctx, scanInfo, c, r, matchChan, logger, func(dest *malcontent.Report) error {
		return scanTargets(ctx, targets, getMaxConcurrency(c.Concurrency), c, dest, matchChan, matchOnce, logger)
	})
}

func prepareScanPath(ctx context.Context, scanPath string, c malcontent.Config, logger *clog.Logger) (scanPathInfo, error) {
	if ctx.Err() != nil {
		return scanPathInfo{}, ctx.Err()
	}

	info := scanPathInfo{
		originalPath:  scanPath,
		effectivePath: scanPath,
	}

	if !c.OCI {
		return info, nil
	}

	info.imageURI = scanPath
	ociPath, err := archive.OCIWithConfig(ctx, info.imageURI, &c)
	if err != nil {
		return info, fmt.Errorf("failed to prepare OCI image for scanning: %w", err)
	}

	info.ociExtractPath = resolveDir(ociPath)
	info.effectivePath = info.ociExtractPath
	logger.Debug("oci image", slog.Any("scanPath", scanPath), slog.Any("ociExtractPath", info.ociExtractPath))

	return info, nil
}

// resolveDir returns dir with symlinks resolved, the form findFilesRecursively
// reports paths below it in, so those paths can be made relative to dir. It
// returns dir unchanged if it cannot be resolved.
func resolveDir(dir string) string {
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved
	}
	return dir
}

// processPaths scans files, found beneath w by walking the scan path
// scanInfo describes, into r.
func processPaths(ctx context.Context, w *walkRoot, files []walkedFile, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	return collectPaths(ctx, scanInfo, c, r, matchChan, logger, func(dest *malcontent.Report) error {
		return runQueue(ctx, w, files, getMaxConcurrency(c.Concurrency), scanInfo, c, dest, matchChan, matchOnce, logger)
	})
}

// collectPaths runs scan, which records reports in the report it is given,
// and settles its outcome in r: a queued exit-criteria match, the context's
// end, or scan's error. An OCI image's files are collected apart from those
// of earlier scan paths, then merged, since exit criteria apply to an image
// as a whole.
func collectPaths(ctx context.Context, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, logger *clog.Logger, scan func(*malcontent.Report) error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	dest := r
	if c.OCI {
		dest = &malcontent.Report{Files: xsync.NewMap[string, *malcontent.FileReport](), Diff: r.Diff, Filter: r.Filter}
	}

	err := scan(dest)

	if c.OCI {
		dest.Files.Range(func(key string, fr *malcontent.FileReport) bool {
			r.Files.Store(key, fr)
			return true
		})
	}

	// The worker that queues an exit-criteria match also fails the group, so
	// the match is read only after every worker has stopped. It outranks the
	// cancellation it causes.
	if m, ok := queuedMatch(matchChan); ok {
		if m.fr != nil {
			renderMatch(ctx, m.fr, c, logger)
		}
		return keepOnlyMatch(r, m)
	}

	// The parent context ending mid-scan leaves the report incomplete.
	if ctxErr := ctx.Err(); ctxErr != nil {
		logger.Debug("scan operation was canceled")
		return ctxErr
	}

	if err != nil {
		return err
	}

	if c.OCI {
		return handleOCIResults(scanInfo.imageURI, dest.Files, r, c)
	}

	return nil
}

// queuedMatch returns the exit-criteria match a worker queued, if any.
func queuedMatch(matchChan chan matchResult) (matchResult, bool) {
	select {
	case m := <-matchChan:
		return m, true
	default:
		return matchResult{}, false
	}
}

// renderMatch renders the file that met the exit criteria when it reaches the
// minimum file risk and has behaviors to show.
func renderMatch(ctx context.Context, fr *malcontent.FileReport, c malcontent.Config, logger *clog.Logger) {
	if c.Renderer == nil || fr.RiskScore < c.MinFileRisk || len(fr.Behaviors) == 0 {
		return
	}
	if err := c.Renderer.File(ctx, fr); err != nil {
		logger.Errorf("render error: %v", err)
	}
}

// keepOnlyMatch replaces the report's files with the exit-criteria match, if
// it has a file report, and returns the match's error. A report with behaviors
// already carries its trimmed display path, which is also its report key.
func keepOnlyMatch(r *malcontent.Report, m matchResult) error {
	r.Files = xsync.NewMap[string, *malcontent.FileReport]()
	if m.fr != nil {
		r.Files.Store(m.fr.Path, m.fr)
	}
	return m.err
}

// concurrencyWarnf logs the warning getMaxConcurrency emits when it caps the
// requested concurrency. Tests replace it to observe that warning.
var concurrencyWarnf = clog.Warnf

func getMaxConcurrency(configured int) int {
	procs := runtime.GOMAXPROCS(0)
	if configured <= 0 {
		return 1
	}
	if configured > procs {
		concurrencyWarnf("--jobs %d capped at %d: scanner concurrency is bound by GOMAXPROCS, so higher values do not increase throughput", configured, procs)
		return procs
	}
	return configured
}

// processPath scans one file found by walking a scan path, extracting it
// first when it is an archive.
func processPath(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	w, _, err := openWalkRoot(path)
	if err != nil {
		return handleSingleFile(ctx, path, scanInfo, c, r, matchChan, matchOnce, logger)
	}
	defer w.close()
	return runQueue(ctx, w, walkedFiles(w, []string{path}), getMaxConcurrency(c.Concurrency), scanInfo, c, r, matchChan, matchOnce, logger)
}

func handleSingleFile(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	return handleSniffedFile(ctx, path, nil, scanInfo, c, r, matchChan, matchOnce, logger, nil)
}

// handleSniffedFile is handleSingleFile for a file that s, when not nil,
// already read, counting it in fileCount, when set, against --max-files. A
// file that cannot be scanned is recorded as skipped; the error returned
// ends the scan.
func handleSniffedFile(ctx context.Context, path string, s *sniffed, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger, fileCount *atomic.Int64) error {
	trimPath := ""
	if c.OCI {
		scanInfo.effectivePath = scanInfo.imageURI
		trimPath = scanInfo.ociExtractPath
	}

	fr, err := processFile(ctx, c, c.RuleFS, path, s, scanInfo.effectivePath, trimPath, logger, fileCount)
	if err != nil {
		return fmt.Errorf("process: %w", err)
	}
	if fr == nil {
		return nil
	}

	key := fileKey(path, scanInfo, c)
	if scanInfo.key != "" {
		fr.Path = key
	}
	// The exit criteria judge what the filters leave of the file.
	TrimFileReport(fr, c.RuleCategories)
	if err := meetExitCriteria(fr, path, c, matchChan, matchOnce); err != nil {
		return err
	}

	r.Files.Store(key, fr)
	if c.Renderer != nil && r.Diff == nil && fr.RiskScore >= c.MinFileRisk && len(fr.Behaviors) > 0 {
		if err := c.Renderer.File(ctx, fr); err != nil {
			return fmt.Errorf("render: %w", err)
		}
	}
	return nil
}

// fileKey returns the report key of a file that is not inside an archive: its
// path, the key of a scan path that names one, or, for an OCI image file, the
// image and the file's path within it. It matches the file's display path.
func fileKey(path string, scanInfo scanPathInfo, c malcontent.Config) string {
	switch {
	case c.OCI:
		return archiveEntryKey(scanInfo.imageURI, CleanPath(path, scanInfo.ociExtractPath), c.TrimPrefixes)
	case scanInfo.key != "":
		return report.DisplayPath(scanInfo.key, c.TrimPrefixes)
	}
	return report.DisplayPath(path, c.TrimPrefixes)
}

// archiveEntryKey returns the report key of entry, a path within the archive
// that reports name archivePath. It joins the two as the entry's display path
// does, "<archive> ∴ <entry>", so entries that share a path in different
// archives keep separate keys.
func archiveEntryKey(archivePath, entry string, trimPrefixes []string) string {
	return fmt.Sprintf("%s ∴ %s", report.DisplayPath(formatPath(archivePath), trimPrefixes), formatPath(entry))
}

func cleanupOCIPath(path string, logger *clog.Logger) {
	if err := file.RemoveAllIn(filepath.Dir(path), filepath.Base(path)); err != nil {
		logger.Errorf("remove %s: %v", path, err)
	}
}

// handleOCIResults applies the exit criteria to the files of one OCI image as
// a whole, with the same outcome for r as a per-file match in other scans.
// Image files are rendered as they are scanned, so the match is not rendered
// again.
func handleOCIResults(imageURI string, image *xsync.Map[string, *malcontent.FileReport], r *malcontent.Report, c malcontent.Config) error {
	match, err := exitIfHitOrMiss(image, imageURI, c.ExitFirstHit, c.ExitFirstMiss, c.MinFileRisk)
	if err != nil {
		return keepOnlyMatch(r, matchResult{fr: match, err: err})
	}
	return nil
}

// handleFileReportError returns the report of the file at path, which err
// kept from being scanned: a skipped report naming the failure, logged, so
// that the scan goes on. The errors that end a scan, its context's end and a
// rule set that does not compile, are returned instead.
func handleFileReportError(err error, path string, logger *clog.Logger) (*malcontent.FileReport, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errRules) {
		return nil, err
	}
	logger.Errorf("unable to scan %s: %v", path, err)
	return &malcontent.FileReport{Path: path, Skipped: skipReason(err)}, nil
}

// skipReason returns the reason a report gives for a file that err kept from
// being scanned.
func skipReason(err error) string {
	var fileErr *FileReportError
	if errors.As(err, &fileErr) && fileErr.Type() == TypeGenerateError {
		return errMsgGenerateFailed
	}
	return fmt.Sprintf("%s: %v", errMsgScanFailed, err)
}

// processFile scans a single output file, rendering live output if available.
// s, when not nil, holds the file already read. A file that cannot be
// scanned yields a skipped report; the error returned ends the scan.
func processFile(ctx context.Context, c malcontent.Config, ruleFS []fs.FS, path string, s *sniffed, scanPath string, archiveRoot string, logger *clog.Logger, fileCount *atomic.Int64) (*malcontent.FileReport, error) {
	logger = logger.With("path", path)

	var fr *malcontent.FileReport
	var err error
	if s != nil {
		fr, err = scanSniffed(ctx, c, path, s, ruleFS, scanPath, archiveRoot, fileCount)
	} else {
		fr, err = scanSinglePath(ctx, c, path, ruleFS, scanPath, archiveRoot, fileCount)
	}
	if err != nil {
		return handleFileReportError(err, path, logger)
	}
	return fr, nil
}

// Scan YARA scans a data source, applying output filters if necessary.
func Scan(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	// Attach the Config to ctx so downstream archive extractors (e.g.
	// ExtractZip's resolveArchiveCaps) observe per-scan caps such as
	// MaxArchiveBytes; without this the extractor falls back to package
	// defaults and ErrArchiveBytesCap can never fire for caller-tuned limits.
	ctx = malcontent.ContextWithConfig(ctx, &c)
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	r, err := recursiveScan(scanCtx, c)
	if errors.Is(err, context.Canceled) {
		return r, fmt.Errorf("scan operation cancelled: %w", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return r, fmt.Errorf("scan operation timed out: %w", err)
	}
	// A met exit condition ends the scan early. The report of the match is
	// filtered like a finished one and returned with it.
	var matchErr error
	if errors.Is(err, ErrMatchedCondition) {
		matchErr, err = err, nil
	}
	// The report so far is returned with the error, so that callers can
	// show what was scanned before reporting why the scan ended.
	if err != nil {
		return r, err
	}
	if r == nil {
		return nil, nil
	}

	ApplyCategoryFilter(r, c.RuleCategories)

	// The scan is complete at this point, so filtering always finishes: a
	// returned report never mixes filtered and unfiltered files. An empty key
	// (a trim prefix equal to a scanned path) is filtered like any other.
	r.Files.Range(func(key string, fr *malcontent.FileReport) bool {
		if fr == nil {
			return true
		}

		if fr.RiskScore < c.MinFileRisk {
			r.Files.Delete(key)
		}

		return true
	})

	// Statistics print to stdout: skip them without a renderer, as the rest of
	// the scan does, and for machine-readable output.
	if matchErr == nil && scanCtx.Err() == nil && c.Stats && c.Renderer != nil && c.Renderer.Name() != "JSON" && c.Renderer.Name() != "YAML" {
		err = render.Statistics(&c, r)
		if err != nil {
			return r, fmt.Errorf("stats: %w", err)
		}
	}
	return r, matchErr
}
