// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/minio/sha256-simd"
	"github.com/puzpuzpuz/xsync/v4"

	yarax "github.com/VirusTotal/yara-x/go"
)

func interactive(c malcontent.Config) bool {
	return c.Renderer != nil && c.Renderer.Name() == "Interactive"
}

var (
	activeScannerPool   atomic.Pointer[rulesScannerPool] // activeScannerPool holds scanners for the most recently scanned rule set.
	compiledRuleCache   atomic.Pointer[yarax.Rules]      // compiledRuleCache are a cache of previously compiled rules.
	compileMu           sync.Mutex                       // compileMu ensures that one caller at a time compiles rules.
	ErrMatchedCondition = errors.New("matched exit criteria")
	scannerPoolMu       sync.Mutex // scannerPoolMu serializes replacing activeScannerPool.
)

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

	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	s := sniffFile(ctx, path, fi)
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
			if err := os.RemoveAll(path); err != nil {
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
			return nil, fmt.Errorf("rules: %w", err)
		}
	}
	// Report generation caches per-rule data for the rule set it is given.
	c.Rules = yrs

	var (
		fc  []byte
		sum [sha256.Size]byte
	)
	if s.content != nil {
		fc = s.content.Bytes()
		sum = sha256.Sum256(capContents(fc))
	}
	matching, err := scanFile(ctx, c, s, path, archiveRoot, fc, sum)
	if err != nil {
		logger.Debug("skipping", slog.Any("error", err))
		return nil, err
	}

	// If running a scan, only generate reports for mrs that satisfy the risk threshold of 3
	// This is a short-circuit that avoids any report generation logic
	risk := 0
	if c.Scan {
		risk = report.HighestMatchRiskRules(matching, kind, path, archiveRoot, c)
		if risk < max(report.HIGH, c.MinFileRisk, c.MinRisk) && !c.QuantityIncreasesRisk {
			return skip("overall risk too low for scan")
		}
	}

	if s.content == nil {
		if fc, err = readCapped(path); err != nil {
			return nil, err
		}
		sum = sha256.Sum256(fc)
	}
	fr, err := report.GenerateRules(ctx, path, matching, c, archiveRoot, logger, capContents(fc), size, hex.EncodeToString(sum[:]), kind, risk)
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
		if len(c.TrimPrefixes) > 0 {
			path = report.TrimPrefixes(path, c.TrimPrefixes)
		}
		return &malcontent.FileReport{Path: path}, nil
	}

	return fr, nil
}

// scanFile returns the rules that match the file s describes: the matches of
// c.Rules and, when c.Rules comes with rules set aside, of the scoped rules
// that apply to the file and the rules for its header. fc and sum are the
// file's contents and their digest when s holds them.
func scanFile(ctx context.Context, c malcontent.Config, s *sniffed, path, archiveRoot string, fc []byte, sum [sha256.Size]byte) ([]*yarax.Rule, error) {
	scanWith := func(rules *yarax.Rules) (*yarax.ScanResults, error) {
		if s.content != nil {
			return scanContent(ctx, rules, fc, sum)
		}
		// Files that could not be read once, or are not regular, are
		// scanned by path as before.
		return withScanner(rules, func(scanner *yarax.Scanner) (*yarax.ScanResults, error) {
			setFileSHA256(scanner, "")
			return scanner.ScanFile(path)
		})
	}
	mrs, err := scanWith(c.Rules)
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
	headers, err := sr.forHeader(fc, s.content != nil)
	if err != nil {
		return nil, err
	}
	sets = append(sets, headers...)
	if len(sets) == 0 {
		return mrs.MatchingRules(), nil
	}
	others := make([]*yarax.ScanResults, 0, len(sets))
	for _, rules := range sets {
		res, err := scanWith(rules)
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

	// handle macOS prefixing temporary directories with /private
	absPath = CleanPath(absPath, "/private")
	pathAbs = CleanPath(pathAbs, "/private")
	archiveRootAbs = CleanPath(archiveRootAbs, "/private")
	// Trim once here: both display paths reuse absPath.
	if len(c.TrimPrefixes) > 0 {
		absPath = report.TrimPrefixes(absPath, c.TrimPrefixes)
	}

	fr.ArchiveRoot = archiveRootAbs
	fr.FullPath = pathAbs
	clean := CleanPath(pathAbs, archiveRootAbs)

	if absPath != "" && absPath != path {
		fr.Path = fmt.Sprintf("%s ∴ %s", absPath, clean)
	}
	return absPath, clean, nil
}

// exitIfHitOrMiss generates the right error if a match is encountered.
func exitIfHitOrMiss(frs *xsync.Map[string, *malcontent.FileReport], scanPath string, errIfHit bool, errIfMiss bool) (*malcontent.FileReport, error) {
	var (
		bList []string
		bMap  = xsync.NewMap[string, bool]()
		count int
		match *malcontent.FileReport
	)
	if frs == nil {
		return nil, nil
	}

	filesScanned := 0

	frs.Range(func(_ string, fr *malcontent.FileReport) bool {
		if fr == nil || fr.Skipped != "" {
			return true
		}

		filesScanned++
		if len(fr.Behaviors) > 0 && match == nil {
			match = fr
		}

		for _, b := range fr.Behaviors {
			count++
			bMap.Store(b.ID, true)
		}

		return true
	})

	bMap.Range(func(key string, _ bool) bool {
		bList = append(bList, key)
		return true
	})
	sort.Strings(bList)

	if filesScanned == 0 {
		return nil, nil
	}

	if errIfHit && count != 0 {
		return match, fmt.Errorf("%s %w", scanPath, ErrMatchedCondition)
	}

	if errIfMiss && count == 0 {
		return nil, fmt.Errorf("%s %w", scanPath, ErrMatchedCondition)
	}
	return nil, nil
}

func CachedRules(ctx context.Context, fss []fs.FS) (*yarax.Rules, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if rules := compiledRuleCache.Load(); rules != nil {
		return rules, nil
	}

	compileMu.Lock()
	defer compileMu.Unlock()
	if rules := compiledRuleCache.Load(); rules != nil {
		return rules, nil
	}
	// A failed or canceled compile is not cached, so the next call tries
	// again.
	yrs, err := compileRules(ctx, fss)
	if err != nil {
		return nil, err
	}
	compiledRuleCache.Store(yrs)
	return yrs, nil
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
	ctx = withResultCache(ctx)

	for _, scanPath := range c.ScanPaths {
		if err := handleScanPath(ctx, scanPath, c, r, matchChan, &matchOnce, logger); err != nil {
			return r, err
		}
	}
	return r, nil
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

	paths, err := findFilesRecursively(ctx, scanInfo.effectivePath)
	if err != nil {
		if len(c.ScanPaths) == 1 {
			return fmt.Errorf("find: %w", err)
		}
		logger.Errorf("find failed: %v", err)
		return nil
	}

	return processPaths(ctx, paths, scanInfo, c, r, matchChan, matchOnce, logger)
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

func processPaths(ctx context.Context, paths []string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Exit criteria apply to an OCI image as a whole, so its files are
	// collected apart from those of earlier scan paths, then merged.
	dest := r
	if c.OCI {
		dest = &malcontent.Report{Files: xsync.NewMap[string, *malcontent.FileReport](), Diff: r.Diff, Filter: r.Filter}
	}

	// Release the path strings once they are queued.
	files := walkedFiles(paths)
	clear(paths)

	err := runQueue(ctx, files, getMaxConcurrency(c.Concurrency), scanInfo, c, dest, matchChan, matchOnce, logger)

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
			TrimFileReport(m.fr, c.RuleCategories)
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
	return runQueue(ctx, walkedFiles([]string{path}), getMaxConcurrency(c.Concurrency), scanInfo, c, r, matchChan, matchOnce, logger)
}

func handleSingleFile(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	return handleSniffedFile(ctx, path, nil, scanInfo, c, r, matchChan, matchOnce, logger)
}

// handleSniffedFile is handleSingleFile for a file that s, when not nil,
// already read.
func handleSniffedFile(ctx context.Context, path string, s *sniffed, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	trimPath := ""
	if c.OCI {
		scanInfo.effectivePath = scanInfo.imageURI
		trimPath = scanInfo.ociExtractPath
	}

	fr, err := processFile(ctx, c, c.RuleFS, path, s, scanInfo.effectivePath, trimPath, logger, nil)
	if err != nil && !interactive(c) {
		r.Files.Store(fileKey(path, scanInfo, c), &malcontent.FileReport{})
		return fmt.Errorf("process: %w", err)
	}
	if fr == nil {
		return nil
	}

	if !c.OCI && (c.ExitFirstHit || c.ExitFirstMiss) {
		frMap := xsync.NewMap[string, *malcontent.FileReport]()
		frMap.Store(path, fr)
		match, err := exitIfHitOrMiss(frMap, path, c.ExitFirstHit, c.ExitFirstMiss)
		if err != nil {
			matchOnce.Do(func() {
				matchChan <- matchResult{fr: match, err: err}
			})
			return err
		}
	}

	TrimFileReport(fr, c.RuleCategories)

	r.Files.Store(fileKey(path, scanInfo, c), fr)
	if c.Renderer != nil && r.Diff == nil && fr.RiskScore >= c.MinFileRisk && len(fr.Behaviors) > 0 {
		if err := c.Renderer.File(ctx, fr); err != nil {
			return fmt.Errorf("render: %w", err)
		}
	}
	return nil
}

// fileKey returns the report key of a file that is not inside an archive: its
// path or, for an OCI image file, the image and the file's path within it. It
// matches the file's display path.
func fileKey(path string, scanInfo scanPathInfo, c malcontent.Config) string {
	if c.OCI {
		return archiveEntryKey(scanInfo.imageURI, CleanPath(path, scanInfo.ociExtractPath), c.TrimPrefixes)
	}
	if len(c.TrimPrefixes) > 0 {
		return report.TrimPrefixes(path, c.TrimPrefixes)
	}
	return path
}

// archiveEntryKey returns the report key of entry, a path within the archive
// that reports name archivePath. It joins the two as the entry's display path
// does, "<archive> ∴ <entry>", so entries that share a path in different
// archives keep separate keys.
func archiveEntryKey(archivePath, entry string, trimPrefixes []string) string {
	archivePath = CleanPath(archivePath, "/private")
	if len(trimPrefixes) > 0 {
		archivePath = report.TrimPrefixes(archivePath, trimPrefixes)
	}
	return fmt.Sprintf("%s ∴ %s", archivePath, formatPath(entry))
}

func cleanupOCIPath(path string, logger *clog.Logger) {
	if err := os.RemoveAll(path); err != nil {
		logger.Errorf("remove %s: %v", path, err)
	}
}

// handleOCIResults applies the exit criteria to the files of one OCI image as
// a whole, with the same outcome for r as a per-file match in other scans.
// Image files are rendered as they are scanned, so the match is not rendered
// again.
func handleOCIResults(imageURI string, image *xsync.Map[string, *malcontent.FileReport], r *malcontent.Report, c malcontent.Config) error {
	match, err := exitIfHitOrMiss(image, imageURI, c.ExitFirstHit, c.ExitFirstMiss)
	if err != nil {
		return keepOnlyMatch(r, matchResult{fr: match, err: err})
	}
	return nil
}

// handleFileReportError returns the appropriate FileReport and error depending on the type of error.
func handleFileReportError(err error, path string, logger *clog.Logger) (*malcontent.FileReport, error) {
	var fileErr *FileReportError
	if !errors.As(err, &fileErr) {
		return nil, fmt.Errorf("failed to handle error for path %s: error type not FileReportError: %w", path, err)
	}

	switch fileErr.Type() {
	case TypeUnknown:
		return nil, fmt.Errorf("unknown error occurred while scanning path %s: %w", path, err)
	case TypeScanError:
		logger.Errorf("scan path: %v", err)
		return nil, fmt.Errorf("scan failed for path %s: %w", path, err)
	case TypeGenerateError:
		return &malcontent.FileReport{
			Path:    path,
			Skipped: errMsgGenerateFailed,
		}, nil
	default:
		return nil, fmt.Errorf("unhandled error type scanning path %s: %w", path, err)
	}
}

// processFile scans a single output file, rendering live output if available.
// s, when not nil, holds the file already read.
func processFile(ctx context.Context, c malcontent.Config, ruleFS []fs.FS, path string, s *sniffed, scanPath string, archiveRoot string, logger *clog.Logger, fileCount *atomic.Int64) (*malcontent.FileReport, error) {
	logger = logger.With("path", path)

	var fr *malcontent.FileReport
	var err error
	if s != nil {
		fr, err = scanSniffed(ctx, c, path, s, ruleFS, scanPath, archiveRoot, fileCount)
	} else {
		fr, err = scanSinglePath(ctx, c, path, ruleFS, scanPath, archiveRoot, fileCount)
	}
	if err != nil && !interactive(c) {
		return handleFileReportError(err, path, logger)
	}

	if fr == nil {
		return nil, nil
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
	if err != nil && !interactive(c) {
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
	if scanCtx.Err() == nil && c.Stats && c.Renderer != nil && c.Renderer.Name() != "JSON" && c.Renderer.Name() != "YAML" {
		err = render.Statistics(&c, r)
		if err != nil {
			return r, fmt.Errorf("stats: %w", err)
		}
	}
	return r, nil
}
