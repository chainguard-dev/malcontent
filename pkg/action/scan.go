// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"golang.org/x/sync/errgroup"

	yarax "github.com/VirusTotal/yara-x/go"
)

const interactive string = "Interactive"

var (
	// compiledRuleCache are a cache of previously compiled rules.
	compiledRuleCache atomic.Pointer[yarax.Rules]
	// compileOnce ensures that we compile rules only once even across threads.
	compileOnce         sync.Once
	ErrMatchedCondition = errors.New("matched exit criteria")
)

// scanSinglePath YARA scans a single path and converts it to a fileReport.
func scanSinglePath(ctx context.Context, c malcontent.Config, path string, ruleFS []fs.FS, absPath string, archiveRoot string) (*malcontent.FileReport, error) {
	logger := clog.FromContext(ctx)
	logger = logger.With("path", path)

	var yrs *yarax.Rules
	var err error
	if c.Rules == nil {
		yrs, err = CachedRules(ctx, ruleFS)
		if err != nil {
			return nil, fmt.Errorf("rules: %w", err)
		}
	} else {
		yrs = c.Rules
	}

	isArchive := archiveRoot != ""
	mime := "<unknown>"
	kind, err := programkind.File(path)
	if err != nil && c.Renderer.Name() != interactive {
		logger.Errorf("file type failure: %s: %s", path, err)
	}
	if kind != nil {
		mime = kind.MIME
	}
	if !c.IncludeDataFiles && kind == nil {
		logger.Debugf("skipping %s [%s]: data file or empty", path, mime)
		return &malcontent.FileReport{Skipped: "data file or empty", Path: path}, nil
	}
	logger = logger.With("mime", mime)

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := fi.Size()
	fc := make([]byte, size)

	if _, err := io.ReadFull(f, fc); err != nil {
		return nil, err
	}

	mrs, err := yrs.Scan(fc)
	if err != nil {
		logger.Debug("skipping", slog.Any("error", err))
		return &malcontent.FileReport{Path: path, Error: fmt.Sprintf("scan: %v", err)}, nil
	}

	fr, err := report.Generate(ctx, path, mrs, c, archiveRoot, logger, fc)
	if err != nil {
		return nil, err
	}

	if fr.Error != "" {
		return &malcontent.FileReport{Path: path, Error: fmt.Sprintf("generate: %v", fr.Error)}, nil
	}

	// Clean up the path if scanning an archive
	var clean string
	if isArchive {
		pathAbs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		archiveRootAbs, err := filepath.Abs(archiveRoot)
		if err != nil {
			return nil, err
		}
		fr.ArchiveRoot = archiveRootAbs
		fr.FullPath = pathAbs
		clean = formatPath(cleanPath(pathAbs, archiveRootAbs))
	}

	// If absPath is provided, use it instead of the path if they are different.
	// This is useful when scanning images and archives.
	if absPath != "" && absPath != path && isArchive {
		if len(c.TrimPrefixes) > 0 {
			absPath = report.TrimPrefixes(absPath, c.TrimPrefixes)
		}
		fr.Path = fmt.Sprintf("%s ∴ %s", absPath, clean)
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
			if fr.Error != "" {
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
	if rules := compiledRuleCache.Load(); rules != nil {
		return rules, nil
	}

	var err error
	compileOnce.Do(func() {
		var yrs *yarax.Rules
		yrs, err = compile.Recursive(ctx, fss)
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
	maxConcurrency := getMaxConcurrency(c.Concurrency)
	pc := createPathChannel(paths)

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	g := setupErrorGroup(maxConcurrency)
	setupMatchHandler(scanCtx, matchChan, c, cancel, logger)

	for path := range pc {
		g.Go(func() error {
			return processPath(scanCtx, path, scanInfo, c, r, matchChan, matchOnce, logger)
		})
	}

	if err := g.Wait(); err != nil {
		return handleScanError(matchChan, r, c, err)
	}

	if c.OCI {
		return handleOCIResults(ctx, scanInfo.imageURI, &r.Files, c, logger)
	}

	return nil
}

func getMaxConcurrency(configured int) int {
	if configured < 1 {
		return 1
	}
	return configured
}

func createPathChannel(paths []string) chan string {
	pc := make(chan string, len(paths))
	for _, path := range paths {
		pc <- path
	}
	close(pc)
	return pc
}

func setupErrorGroup(maxConcurrency int) *errgroup.Group {
	g := &errgroup.Group{}
	g.SetLimit(maxConcurrency)
	return g
}

func setupMatchHandler(ctx context.Context, matchChan chan matchResult, c malcontent.Config, cancel context.CancelFunc, logger *clog.Logger) {
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
	frs, err := processArchive(ctx, c, c.RuleFS, path, logger)
	if err != nil {
		logger.Errorf("unable to process %s: %v", path, err)
		return err
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
	if err != nil && c.Renderer.Name() != interactive {
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

	tmpRoot, err := archive.ExtractArchiveToTempDir(ctx, archivePath)
	if err != nil {
		return nil, fmt.Errorf("extract to temp: %w", err)
	}
	// Ensure that tmpRoot is removed before returning if created successfully
	if tmpRoot != "" {
		defer func() {
			if err := os.RemoveAll(tmpRoot); err != nil {
				logger.Errorf("remove %s: %v", tmpRoot, err)
			}
		}()
	}
	// macOS will prefix temporary directories with `/private`
	// update tmpRoot with this prefix to allow strings.TrimPrefix to work
	if runtime.GOOS == "darwin" {
		tmpRoot = fmt.Sprintf("/private%s", tmpRoot)
	}

	extractedPaths, err := findFilesRecursively(ctx, tmpRoot)
	if err != nil {
		return nil, fmt.Errorf("find: %w", err)
	}

	maxConcurrency := getMaxConcurrency(c.Concurrency)
	g := setupErrorGroup(maxConcurrency)

	ep := createPathChannel(extractedPaths)
	for path := range ep {
		g.Go(func() error {
			fr, err := processFile(ctx, c, rfs, path, archivePath, tmpRoot, logger)
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

// processFile scans a single output file, rendering live output if available.
func processFile(ctx context.Context, c malcontent.Config, ruleFS []fs.FS, path string, scanPath string, archiveRoot string, logger *clog.Logger) (*malcontent.FileReport, error) {
	logger = logger.With("path", path)

	fr, err := scanSinglePath(ctx, c, path, ruleFS, scanPath, archiveRoot)
	if err != nil && c.Renderer.Name() != interactive {
		logger.Errorf("scan path: %v", err)
		return nil, err
	}

	if fr == nil {
		logger.Debugf("%s returned nil result", path)
		return nil, nil
	}

	if fr.Error != "" && c.Renderer.Name() != interactive {
		logger.Errorf("scan error: %s", fr.Error)
		return nil, fmt.Errorf("report error: %v", fr.Error)
	}

	return fr, nil
}

// Scan YARA scans a data source, applying output filters if necessary.
func Scan(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	r, err := recursiveScan(ctx, c)
	if err != nil && (c.Renderer == nil || c.Renderer.Name() != interactive) {
		return r, err
	}
	r.Files.Range(func(key, value any) bool {
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
	if c.Stats && c.Renderer.Name() != "JSON" && c.Renderer.Name() != "YAML" {
		err = render.Statistics(&c, r)
		if err != nil {
			return r, fmt.Errorf("stats: %w", err)
		}
	}
	return r, nil
}
