// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"bytes"
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
	"syscall"

	"github.com/minio/sha256-simd"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"golang.org/x/sync/errgroup"

	yarax "github.com/VirusTotal/yara-x/go"
)

func interactive(c malcontent.Config) bool {
	return c.Renderer != nil && c.Renderer.Name() == "Interactive"
}

var (
	// compiledRuleCache are a cache of previously compiled rules.
	compiledRuleCache atomic.Pointer[yarax.Rules]
	// compileOnce ensures that we compile rules only once even across threads.
	compileOnce         sync.Once
	ErrMatchedCondition = errors.New("matched exit criteria")
	// initializeOnce ensures that the file and scanner pools are only initialized once.
	initializeOnce sync.Once
	scannerPool    *pool.ScannerPool
	maxMmapSize    int64 = 1 << 31
)

// scanFD scans a file descriptor using memory mapping for efficient large file handling.
// This avoids loading the entire file into memory while still using yara-x's byte slice scanning.
// scanFD also returns the file's contents for match string extraction,
// as well as the file's size and its checksum which were originally calculated separately as part of report generation.
func scanFD(scanner *yarax.Scanner, fd uintptr, size int64, logger *clog.Logger) ([]byte, *yarax.ScanResults, string, error) {
	stat := &syscall.Stat_t{}
	if err := syscall.Fstat(int(fd), stat); err != nil {
		return nil, nil, "", fmt.Errorf("fstat failed: %w", err)
	}

	data, err := syscall.Mmap(int(fd), 0, int(size), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return nil, nil, "", fmt.Errorf("mmap failed: %w", err)
	}

	defer func() {
		if unmapErr := syscall.Munmap(data); unmapErr != nil {
			logger.Error("failed to unmap memory", "error", unmapErr)
		}
	}()

	h := sha256.New()
	h.Write(data)
	checksum := fmt.Sprintf("%x", h.Sum(nil))

	// Create a copy of the data to return since the mmap will be unmapped
	// This is necessary because report generation needs access to file content
	// for match string extraction
	fc := bytes.Clone(data)

	mrs, err := scanner.Scan(data)
	if err != nil {
		return nil, nil, "", err
	}

	return fc, mrs, checksum, err
}

// scanSinglePath YARA scans a single path and converts it to a fileReport.
func scanSinglePath(ctx context.Context, c malcontent.Config, path string, ruleFS []fs.FS, absPath string, archiveRoot string) (*malcontent.FileReport, error) {
	if ctx.Err() != nil {
		return &malcontent.FileReport{}, ctx.Err()
	}

	logger := clog.FromContext(ctx)
	logger = logger.With("path", path)

	isArchive := archiveRoot != ""

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fd := f.Fd()

	fi, err := f.Stat()
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

	if size > maxMmapSize {
		logger.Warn("file exceeds mmap limit, scanning first portion only",
			"size", size, "limit", maxMmapSize)
		size = maxMmapSize
	}

	mime := "<unknown>"
	kind, err := programkind.File(path)
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

	var yrs *yarax.Rules
	if c.Rules != nil {
		yrs = c.Rules
	} else {
		yrs, err = CachedRules(ctx, ruleFS)
		if err != nil {
			return nil, fmt.Errorf("rules: %w", err)
		}
	}

	initializeOnce.Do(func() {
		// always create one scanner per available CPU core since the pool is used for the duration of
		// a scan which may involve concurrent scans of individual files
		scannerPool = pool.NewScannerPool(yrs, getMaxConcurrency(runtime.GOMAXPROCS(0)))
	})
	scanner := scannerPool.Get(yrs)

	fc, mrs, checksum, err := scanFD(scanner, fd, size, logger)
	if err != nil {
		logger.Debug("skipping", slog.Any("error", err))
		return nil, err
	}

	// If running a scan, only generate reports for mrs that satisfy the risk threshold of 3
	// This is a short-circuit that avoids any report generation logic
	risk := report.HighestMatchRisk(mrs)
	threshold := max(report.HIGH, c.MinFileRisk, c.MinRisk)
	if c.Scan && risk < threshold && !c.QuantityIncreasesRisk {
		fr := &malcontent.FileReport{Skipped: "overall risk too low for scan", Path: path}
		if isArchive {
			os.RemoveAll(path)
		}
		return fr, nil
	}

	fr, err := report.Generate(ctx, path, mrs, c, archiveRoot, logger, fc, size, checksum, kind, risk)
	if err != nil {
		return nil, NewFileReportError(err, path, TypeGenerateError)
	}

	defer func() {
		f.Close()
		scannerPool.Put(scanner)
		fc = nil
		mrs = nil
	}()

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
		if runtime.GOOS == "darwin" {
			pathAbs = strings.TrimPrefix(pathAbs, "/private")
			archiveRootAbs = strings.TrimPrefix(archiveRootAbs, "/private")
		}
		fr.ArchiveRoot = archiveRootAbs
		fr.FullPath = pathAbs
		clean = formatPath(cleanPath(pathAbs, archiveRootAbs))

		if absPath != "" && absPath != path && (isArchive || c.OCI) {
			if len(c.TrimPrefixes) > 0 {
				absPath = report.TrimPrefixes(absPath, c.TrimPrefixes)
			}
			fr.Path = fmt.Sprintf("%s ∴ %s", absPath, clean)
		}
	}

	if len(fr.Behaviors) == 0 {
		if len(c.TrimPrefixes) > 0 {
			if isArchive {
				absPath = report.TrimPrefixes(absPath, c.TrimPrefixes)
			} else {
				path = report.TrimPrefixes(absPath, c.TrimPrefixes)
			}
		}
		if isArchive {
			return &malcontent.FileReport{Path: fmt.Sprintf("%s ∴ %s", absPath, clean)}, nil
		}
		return &malcontent.FileReport{Path: path}, nil
	}

	return fr, nil
}

// exitIfHitOrMiss generates the right error if a match is encountered.
func exitIfHitOrMiss(frs *sync.Map, scanPath string, errIfHit bool, errIfMiss bool) (*malcontent.FileReport, error) {
	var (
		bList []string
		bMap  sync.Map
		count int
		match *malcontent.FileReport
	)
	if frs == nil {
		return nil, nil
	}

	filesScanned := 0

	frs.Range(func(_, value any) bool {
		if value == nil {
			return true
		}
		if fr, ok := value.(*malcontent.FileReport); ok {
			if fr.Skipped != "" {
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
		}
		return true
	})

	bMap.Range(func(key, _ any) bool {
		if key == nil {
			return true
		}
		if k, ok := key.(string); ok {
			bList = append(bList, k)
		}
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
		Files: sync.Map{},
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

	scanInfo, err := prepareScanPath(ctx, scanPath, c.OCI, logger)
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

func prepareScanPath(ctx context.Context, scanPath string, isOCI bool, logger *clog.Logger) (scanPathInfo, error) {
	if ctx.Err() != nil {
		return scanPathInfo{}, ctx.Err()
	}

	info := scanPathInfo{
		originalPath:  scanPath,
		effectivePath: scanPath,
	}

	if !isOCI {
		return info, nil
	}

	info.imageURI = scanPath
	ociPath, err := archive.OCI(ctx, info.imageURI)
	if err != nil {
		return info, fmt.Errorf("failed to prepare OCI image for scanning: %w", err)
	}

	info.ociExtractPath = ociPath
	info.effectivePath = ociPath
	logger.Debug("oci image", slog.Any("scanPath", scanPath), slog.Any("ociExtractPath", ociPath))

	return info, nil
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
	defer cancel()

	go func() {
		<-ctx.Done()
		logger.Debug("parent context canceled, stopping scan")
		cancel()
	}()

	g, gCtx := errgroup.WithContext(scanCtx)
	g.SetLimit(maxConcurrency)

	setupMatchHandler(gCtx, matchChan, c, cancel, logger)

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
			return processPath(gCtx, path, scanInfo, c, r, matchChan, matchOnce, logger)
		})
	}

	err := g.Wait()

	if scanCtx.Err() != nil && errors.Is(scanCtx.Err(), context.Canceled) {
		logger.Debug("scan operation was canceled")
		return scanCtx.Err()
	}

	if err != nil {
		return handleScanError(matchChan, r, c, err)
	}

	if c.OCI && ctx.Err() == nil {
		return handleOCIResults(ctx, scanInfo.imageURI, &r.Files, c, logger)
	}

	return nil
}

func getMaxConcurrency(configured int) int {
	return max(1, configured)
}

func setupMatchHandler(ctx context.Context, matchChan chan matchResult, c malcontent.Config, cancel context.CancelFunc, logger *clog.Logger) {
	if ctx.Err() != nil {
		return
	}

	go func() {
		select {
		case match := <-matchChan:
			if match.fr != nil && c.Renderer != nil && match.fr.RiskScore >= c.MinFileRisk {
				if err := c.Renderer.File(ctx, match.fr); err != nil {
					logger.Errorf("render error: %v", err)
				}
			}
			cancel()
		case <-ctx.Done():
			return
		}
	}()
}

func processPath(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if programkind.IsSupportedArchive(path) {
			return handleArchiveFile(ctx, path, c, r, matchChan, matchOnce, logger)
		}
		return handleSingleFile(ctx, path, scanInfo, c, r, matchChan, matchOnce, logger)
	}
}

func handleArchiveFile(ctx context.Context, path string, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	frs, err := processArchive(ctx, c, c.RuleFS, path, logger)
	if err != nil {
		logger.Errorf("unable to process %s: %v", path, err)
		// Avoid failing an entire scan when encountering problematic archives
		// e.g., joblib_0.8.4_compressed_pickle_py27_np17.gz: not a valid gzip archive
		if c.ExitExtraction {
			return err
		}
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

	//nolint:nestif // ignore complexity of 14
	if frs != nil {
		frs.Range(func(key, value any) bool {
			if ctx.Err() != nil {
				return false
			}
			if key == nil || value == nil {
				return true
			}
			if k, ok := key.(string); ok {
				if fr, ok := value.(*malcontent.FileReport); ok {
					if len(c.TrimPrefixes) > 0 {
						k = report.TrimPrefixes(k, c.TrimPrefixes)
					}
					r.Files.Store(k, fr)
					if c.Renderer != nil && r.Diff == nil && fr.RiskScore >= c.MinFileRisk {
						if err := c.Renderer.File(ctx, fr); err != nil {
							logger.Errorf("render error: %v", err)
						}
					}
				}
			}
			return true
		})
	}
	return nil
}

func handleSingleFile(ctx context.Context, path string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, matchOnce *sync.Once, logger *clog.Logger) error {
	trimPath := ""
	if c.OCI {
		scanInfo.effectivePath = scanInfo.imageURI
		trimPath = scanInfo.ociExtractPath
	}

	fr, err := processFile(ctx, c, c.RuleFS, path, scanInfo.effectivePath, trimPath, logger)
	if err != nil && !interactive(c) {
		if len(c.TrimPrefixes) > 0 {
			path = report.TrimPrefixes(path, c.TrimPrefixes)
		}
		r.Files.Store(path, &malcontent.FileReport{})
		return fmt.Errorf("process: %w", err)
	}
	if fr == nil {
		return nil
	}

	if !c.OCI && (c.ExitFirstHit || c.ExitFirstMiss) {
		var frMap sync.Map
		frMap.Store(path, fr)
		match, err := exitIfHitOrMiss(&frMap, path, c.ExitFirstHit, c.ExitFirstMiss)
		if err != nil {
			matchOnce.Do(func() {
				matchChan <- matchResult{fr: match, err: err}
			})
			return err
		}
	}

	if len(c.TrimPrefixes) > 0 {
		path = report.TrimPrefixes(path, c.TrimPrefixes)
	}
	r.Files.Store(path, fr)
	if c.Renderer != nil && r.Diff == nil && fr.RiskScore >= c.MinFileRisk {
		if err := c.Renderer.File(ctx, fr); err != nil {
			return fmt.Errorf("render: %w", err)
		}
	}
	return nil
}

func handleScanError(matchChan chan matchResult, r *malcontent.Report, c malcontent.Config, err error) error {
	select {
	case match := <-matchChan:
		// Clear existing entries and store only the match result
		r.Files = sync.Map{}
		if match.fr != nil {
			if len(c.TrimPrefixes) > 0 {
				match.fr.Path = report.TrimPrefixes(match.fr.Path, c.TrimPrefixes)
			}
			r.Files.Store(match.fr.Path, match.fr)
		}
		return match.err
	default:
		return err
	}
}

func cleanupOCIPath(path string, logger *clog.Logger) {
	if err := os.RemoveAll(path); err != nil {
		logger.Errorf("remove %s: %v", path, err)
	}
}

func handleOCIResults(ctx context.Context, imageURI string, files *sync.Map, c malcontent.Config, logger *clog.Logger) error {
	match, err := exitIfHitOrMiss(files, imageURI, c.ExitFirstHit, c.ExitFirstMiss)
	if err != nil && match != nil && c.Renderer != nil && match.RiskScore >= c.MinFileRisk {
		if renderErr := c.Renderer.File(ctx, match); renderErr != nil {
			logger.Errorf("render error: %v", renderErr)
		}
		return err
	}
	return nil
}

// processArchive extracts and scans a single archive file.
func processArchive(ctx context.Context, c malcontent.Config, rfs []fs.FS, archivePath string, logger *clog.Logger) (*sync.Map, error) {
	logger = logger.With("archivePath", archivePath)

	var frs sync.Map

	tmpRoot, err := archive.ExtractArchiveToTempDir(ctx, c, archivePath)
	if err != nil {
		return nil, fmt.Errorf("extract to temp: %w", err)
	}
	// Ensure that tmpRoot is removed before returning if created successfully
	defer func() {
		if err := os.RemoveAll(tmpRoot); err != nil {
			logger.Errorf("remove %s: %v", tmpRoot, err)
		}
	}()

	// macOS will prefix temporary directories with `/private`
	// update tmpRoot (if populated) with this prefix to allow strings.TrimPrefix to work
	if runtime.GOOS == "darwin" && tmpRoot != "" {
		tmpRoot = fmt.Sprintf("/private%s", tmpRoot)
	}

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
			fr, err := processFile(gCtx, c, rfs, path, archivePath, tmpRoot, logger)
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

	return &frs, nil
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
func processFile(ctx context.Context, c malcontent.Config, ruleFS []fs.FS, path string, scanPath string, archiveRoot string, logger *clog.Logger) (*malcontent.FileReport, error) {
	logger = logger.With("path", path)

	fr, err := scanSinglePath(ctx, c, path, ruleFS, scanPath, archiveRoot)
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
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	r, err := recursiveScan(scanCtx, c)
	if errors.Is(err, context.Canceled) {
		return r, fmt.Errorf("scan operation cancelled: %w", err)
	}
	if err != nil && !interactive(c) {
		return r, err
	}

	if r != nil {
		r.Files.Range(func(key, value any) bool {
			if scanCtx.Err() != nil {
				return false
			}
			if key == nil || value == nil {
				return true
			}
			if fr, ok := value.(*malcontent.FileReport); ok {
				if fr.RiskScore < c.MinFileRisk {
					r.Files.Delete(key)
				}
			}
			return true
		})
	}
	if scanCtx.Err() == nil && c.Stats && c.Renderer.Name() != "JSON" && c.Renderer.Name() != "YAML" {
		err = render.Statistics(&c, r)
		if err != nil {
			return r, fmt.Errorf("stats: %w", err)
		}
	}
	return r, nil
}
