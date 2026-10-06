// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
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
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/minio/sha256-simd"
	"github.com/puzpuzpuz/xsync/v4"
	"golang.org/x/sync/errgroup"

	yarax "github.com/VirusTotal/yara-x/go"
)

func interactive(c malcontent.Config) bool {
	return c.Renderer != nil && c.Renderer.Name() == "Interactive"
}

var (
	activeScannerPool   atomic.Pointer[rulesScannerPool] // activeScannerPool holds scanners for the most recently scanned rule set.
	compiledRuleCache   atomic.Pointer[yarax.Rules]      // compiledRuleCache are a cache of previously compiled rules.
	compileOnce         sync.Once                        // compileOnce ensures that we compile rules only once even across threads.
	ErrMatchedCondition = errors.New("matched exit criteria")
	readPool            *pool.BufferPool
	scannerPoolMu       sync.Mutex // scannerPoolMu serializes replacing activeScannerPool.
)

func init() {
	readPool = pool.NewBufferPool(runtime.GOMAXPROCS(0))
}

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

	logger := clog.FromContext(ctx)
	logger = logger.With("path", path)

	isArchive := archiveRoot != ""

	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	size := fi.Size()
	if size == 0 {
		fr := &malcontent.FileReport{Skipped: "zero-sized file", Path: path}
		if isArchive {
			defer os.RemoveAll(path)
		}
		return fr, nil
	}

	mime := "<unknown>"
	kind, err := programkind.File(ctx, path)
	if err != nil && !interactive(c) {
		logger.Errorf("file type failure: %s: %s", path, err)
	}
	if kind != nil {
		mime = kind.MIME
	}

	if !c.IncludeDataFiles && kind == nil {
		logger.Debugf("skipping %s [%s]: data file or empty", path, mime)
		fr := &malcontent.FileReport{Skipped: "data file or empty", Path: path}
		// Immediately remove skipped files within archives
		if isArchive {
			defer os.RemoveAll(path)
		}
		return fr, nil
	}
	logger = logger.With("mime", mime)

	if fileCount != nil {
		count := fileCount.Add(1)
		if c.MaxScanFiles > 0 && count > int64(c.MaxScanFiles) {
			logger.Warnf("skipping %s: file count %d exceeds limit %d", path, count, c.MaxScanFiles)
			if isArchive {
				defer os.RemoveAll(path)
			}
			return &malcontent.FileReport{Skipped: "max file count exceeded", Path: path}, nil
		}
	}

	var yrs *yarax.Rules
	if c.Rules != nil {
		yrs = c.Rules
	} else {
		yrs, err = CachedRules(ctx, ruleFS)
		if err != nil {
			return nil, fmt.Errorf("rules: %w", err)
		}
	}

	sp := acquireScannerPool(yrs)
	defer sp.release()
	scanner := sp.scanners.Get(yrs)
	defer sp.scanners.Put(scanner)

	mrs, err := scanner.ScanFile(path)
	if err != nil {
		logger.Debug("skipping", slog.Any("error", err))
		return nil, err
	}

	// If running a scan, only generate reports for mrs that satisfy the risk threshold of 3
	// This is a short-circuit that avoids any report generation logic
	risk := report.HighestMatchRisk(mrs, kind, path, archiveRoot, c)
	threshold := max(report.HIGH, c.MinFileRisk, c.MinRisk)
	if c.Scan && risk < threshold && !c.QuantityIncreasesRisk {
		fr := &malcontent.FileReport{Skipped: "overall risk too low for scan", Path: path}
		if isArchive {
			if rmErr := os.RemoveAll(path); rmErr != nil {
				logger.Warnf("remove skipped archive entry %s: %v", path, rmErr)
			}
		}
		return fr, nil
	}

	// create a buffer sized to the minimum of the file's size or the default ReadBuffer
	// only do so if we actually need to retrieve the file's contents
	buf := readPool.Get(min(size, file.ReadBuffer)) //nolint:nilaway // the buffer pool is initialized in init()
	defer readPool.Put(buf)

	// #nosec G304 -- path originates from findFilesRecursively over caller-supplied scan paths or archive temp dirs already validated by ValidateResolvedPath/IsValidPath during extraction
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fc, err := file.GetContents(f, buf)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	_, err = h.Write(fc)
	if err != nil {
		return nil, err
	}
	checksum := fmt.Sprintf("%x", h.Sum(nil))

	fr, err := report.Generate(ctx, path, mrs, c, archiveRoot, logger, fc, size, checksum, kind, risk)
	if err != nil {
		return nil, NewFileReportError(err, path, TypeGenerateError)
	}

	// Clean up the path if scanning an archive
	var clean string
	if isArchive || c.OCI {
		pathAbs, err := filepath.Abs(path)
		if err != nil {
			return nil, NewFileReportError(err, path, TypeGenerateError)
		}
		archiveRootAbs, err := filepath.Abs(archiveRoot)
		if err != nil {
			return nil, NewFileReportError(err, path, TypeGenerateError)
		}

		// handle macOS prefixing temporary directories with /private
		absPath = CleanPath(absPath, "/private")
		pathAbs = CleanPath(pathAbs, "/private")
		archiveRootAbs = CleanPath(archiveRootAbs, "/private")
		// Trim once here: both display paths below reuse absPath.
		if len(c.TrimPrefixes) > 0 {
			absPath = report.TrimPrefixes(absPath, c.TrimPrefixes)
		}

		fr.ArchiveRoot = archiveRootAbs
		fr.FullPath = pathAbs
		clean = CleanPath(pathAbs, archiveRootAbs)

		if absPath != "" && absPath != path {
			fr.Path = fmt.Sprintf("%s ∴ %s", absPath, clean)
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

	var err error
	compileOnce.Do(func() {
		var yrs *yarax.Rules
		yrs, err = compile.RecursiveCached(ctx, fss)
		if err != nil {
			err = fmt.Errorf("compile: %w", err)
			return
		}
		compiledRuleCache.Store(yrs)
	})

	if err != nil {
		return nil, err
	}

	return compiledRuleCache.Load(), nil
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

	// adjust concurrency if the number of paths to scan
	// is lower than the configured value
	numPaths := len(paths)
	maxConcurrency := getMaxConcurrency(min(c.Concurrency, numPaths))

	scanCtx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Go(func() {
		<-scanCtx.Done()
		logger.Debug("parent context canceled, stopping scan")
		cancel()
	})
	defer func() {
		cancel()
		wg.Wait()
	}()

	g, gCtx := errgroup.WithContext(scanCtx)
	g.SetLimit(maxConcurrency)

	// Exit criteria apply to an OCI image as a whole, so its files are
	// collected apart from those of earlier scan paths, then merged.
	dest := r
	if c.OCI {
		dest = &malcontent.Report{Files: xsync.NewMap[string, *malcontent.FileReport](), Diff: r.Diff, Filter: r.Filter}
	}

	pc := make(chan string, numPaths)
	go func() {
		defer close(pc)
		for _, path := range paths {
			select {
			case <-gCtx.Done():
				return
			case pc <- path:
			}
		}
	}()

	// Zero-out the path strings and empty the slice once read into the path channel
	defer func() {
		clear(paths)
		paths = paths[:0]
	}()

	for path := range pc {
		g.Go(func() error {
			if gCtx.Err() != nil {
				return scanCtx.Err()
			}
			return processPath(gCtx, path, scanInfo, c, dest, matchChan, matchOnce, logger)
		})
	}

	err := g.Wait()

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

func processPath(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if programkind.IsSupportedArchive(ctx, path) {
			return handleArchiveFile(ctx, path, scanInfo, c, r, matchChan, matchOnce, logger)
		}
		return handleSingleFile(ctx, path, scanInfo, c, r, matchChan, matchOnce, logger)
	}
}

func handleArchiveFile(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Reports name an archive inside an OCI image by the image and its path
	// within it rather than by the temporary extraction path.
	displayPath := path
	if c.OCI {
		displayPath = fmt.Sprintf("%s ∴ %s", scanInfo.imageURI, CleanPath(path, scanInfo.ociExtractPath))
	}

	frs, err := processArchive(ctx, c, c.RuleFS, path, displayPath, logger)
	if err != nil {
		logger.Errorf("unable to process %s: %v", path, err)
		// Avoid failing an entire scan when encountering problematic archives
		// e.g., joblib_0.8.4_compressed_pickle_py27_np17.gz: not a valid gzip archive
		if c.ExitExtraction {
			return err
		}
	}

	if frs == nil {
		return nil
	}

	if !c.OCI && (c.ExitFirstHit || c.ExitFirstMiss) {
		match, err := exitIfHitOrMiss(frs, path, c.ExitFirstHit, c.ExitFirstMiss)
		if err != nil {
			matchOnce.Do(func() {
				matchChan <- matchResult{fr: match, err: err}
			})
			return err
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

		r.Files.Store(archiveEntryKey(displayPath, entry, c.TrimPrefixes), fr)
		if c.Renderer != nil && r.Diff == nil && fr.RiskScore >= c.MinFileRisk && len(fr.Behaviors) > 0 {
			if err := c.Renderer.File(ctx, fr); err != nil {
				logger.Errorf("render error: %v", err)
			}
		}

		return true
	})

	return nil
}

func handleSingleFile(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	trimPath := ""
	if c.OCI {
		scanInfo.effectivePath = scanInfo.imageURI
		trimPath = scanInfo.ociExtractPath
	}

	fr, err := processFile(ctx, c, c.RuleFS, path, scanInfo.effectivePath, trimPath, logger, nil)
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

// processArchive extracts and scans a single archive file, keying each entry's
// report by its path within the archive. displayPath names the archive in the
// entries' display paths.
func processArchive(ctx context.Context, c malcontent.Config, rfs []fs.FS, archivePath string, displayPath string, logger *clog.Logger) (*xsync.Map[string, *malcontent.FileReport], error) {
	logger = logger.With("archivePath", archivePath)

	frs := xsync.NewMap[string, *malcontent.FileReport]()
	var fileCount atomic.Int64

	extractDir, err := archive.ExtractArchiveToTempDir(ctx, c, archivePath)
	if err != nil {
		return nil, fmt.Errorf("extract to temp: %w", err)
	}
	// Ensure that the extraction directory is removed before returning if created successfully
	defer func() {
		if err := os.RemoveAll(extractDir); err != nil {
			logger.Errorf("remove %s: %v", extractDir, err)
		}
	}()

	// findFilesRecursively reports paths below the resolved directory (for
	// example when TMPDIR is reached through a symlink, or macOS' /var), so
	// entry paths are taken relative to the resolved form.
	tmpRoot := resolveDir(extractDir)

	extractedPaths, err := findFilesRecursively(ctx, tmpRoot)
	if err != nil {
		return nil, fmt.Errorf("find: %w", err)
	}

	numPaths := len(extractedPaths)

	ep := make(chan string, numPaths)
	go func() {
		defer close(ep)
		for _, path := range extractedPaths {
			select {
			case <-ctx.Done():
				return
			case ep <- path:
			}
		}
	}()

	// adjust concurrency if the number of paths to scan
	// is lower than the configured value
	maxConcurrency := getMaxConcurrency(min(c.Concurrency, numPaths))
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	g, gCtx := errgroup.WithContext(scanCtx)
	g.SetLimit(maxConcurrency)

	for path := range ep {
		g.Go(func() error {
			fr, err := processFile(gCtx, c, rfs, path, displayPath, tmpRoot, logger, &fileCount)
			if err != nil {
				return err
			}
			if fr != nil {
				clean := strings.TrimPrefix(path, tmpRoot)
				frs.Store(clean, fr)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return frs, nil
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
func processFile(ctx context.Context, c malcontent.Config, ruleFS []fs.FS, path string, scanPath string, archiveRoot string, logger *clog.Logger, fileCount *atomic.Int64) (*malcontent.FileReport, error) {
	logger = logger.With("path", path)

	fr, err := scanSinglePath(ctx, c, path, ruleFS, scanPath, archiveRoot, fileCount)
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
