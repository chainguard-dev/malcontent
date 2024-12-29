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

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/archive"
	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/pkg/report"

	"github.com/hillu/go-yara/v4"
	"golang.org/x/sync/errgroup"
)

var (
	// compiledRuleCache are a cache of previously compiled rules.
	compiledRuleCache *yara.Rules
	// compileOnce ensures that we compile rules only once even across threads.
	compileOnce         sync.Once
	ErrMatchedCondition = errors.New("matched exit criteria")
)

// findFilesRecursively returns a list of files found recursively within a path.
func findFilesRecursively(ctx context.Context, rootPath string) ([]string, error) {
	logger := clog.FromContext(ctx)
	var files []string

	// Follow symlink if provided at the root
	root, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		// If the target does not exist, log the error but return gracefully
		// This is useful when scanning -compat packages
		if os.IsNotExist(err) {
			logger.Debugf("symlink target does not exist: %s", err.Error())
			return nil, nil
		}
		// Allow /proc/XXX/exe to be scanned even if symlink is not resolveable
		if strings.HasPrefix(rootPath, "/proc/") {
			root = rootPath
		} else {
			return nil, fmt.Errorf("eval %q: %w", rootPath, err)
		}
	}

	err = filepath.WalkDir(root,
		func(path string, info os.DirEntry, err error) error {
			if err != nil {
				logger.Errorf("error: %s: %s", path, err)
				return nil
			}
			if info.IsDir() || strings.Contains(path, "/.git/") {
				return nil
			}

			files = append(files, path)
			return nil
		})
	return files, err
}

// cleanPath removes the temporary directory prefix from the path.
func cleanPath(path string, prefix string) (string, error) {
	pathEval, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	prefixEval, err := filepath.EvalSymlinks(prefix)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(pathEval, prefixEval), nil
}

// formatPath formats the path for display.
func formatPath(path string) string {
	if strings.Contains(path, "\\") {
		path = strings.ReplaceAll(path, "\\", "/")
	}
	return path
}

// scanSinglePath YARA scans a single path and converts it to a fileReport.
func scanSinglePath(ctx context.Context, c malcontent.Config, path string, ruleFS []fs.FS, absPath string, archiveRoot string) (*malcontent.FileReport, error) {
	logger := clog.FromContext(ctx)
	var mrs yara.MatchRules
	logger = logger.With("path", path)

	isArchive := archiveRoot != ""

	mime := "<unknown>"
	kind, err := programkind.File(path)
	if err != nil && c.Renderer.Name() != "Interactive" {
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
	if err != nil && c.Renderer.Name() != "Interactive" {
		return nil, err
	}
	defer f.Close()
	fd := f.Fd()

	// For non-refresh scans, c.Rules will be nil
	// For refreshes, the rules _should_ be compiled by the time we get here
	var yrs *yara.Rules
	if c.Rules == nil {
		yrs, err = CachedRules(ctx, ruleFS)
		if err != nil {
			return nil, fmt.Errorf("rules: %w", err)
		}
	} else {
		yrs = c.Rules
	}
	if err := yrs.ScanFileDescriptor(fd, 0, 0, &mrs); err != nil {
		logger.Debug("skipping", slog.Any("error", err))
		return &malcontent.FileReport{Path: path, Error: fmt.Sprintf("scan: %v", err)}, nil
	}

	fr, err := report.Generate(ctx, path, mrs, c, archiveRoot, logger)
	if err != nil {
		return nil, err
	}

	// Clean up the path if scanning an archive
	var clean string
	if isArchive {
		fr.ArchiveRoot = archiveRoot
		fr.FullPath = path
		clean, err = cleanPath(path, archiveRoot)
		if err != nil {
			return nil, err
		}
		clean = formatPath(strings.TrimPrefix(clean, archiveRoot))
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
		// Ensure that files within archives with no behaviors are formatted consistently
		if isArchive {
			return &malcontent.FileReport{Path: fmt.Sprintf("%s ∴ %s", absPath, clean)}, nil
		}
		return &malcontent.FileReport{Path: path}, nil
	}

	return &fr, nil
}

// errIfMatch generates the right error if a match is encountered.
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

func CachedRules(ctx context.Context, fss []fs.FS) (*yara.Rules, error) {
	if compiledRuleCache != nil {
		return compiledRuleCache, nil
	}

	var yrs *yara.Rules
	var err error
	compileOnce.Do(func() {
		yrs, err = compile.Recursive(ctx, fss)
		if err != nil {
			err = fmt.Errorf("compile: %w", err)
		}

		compiledRuleCache = yrs
	})
	return compiledRuleCache, err
}

type matchResult struct {
	fr  *malcontent.FileReport
	err error
}
// recursiveScan recursively YARA scans the configured paths - handling archives and OCI images.
//
//nolint:gocognit,cyclop,nestif // ignoring complexity of 101,38
func recursiveScan(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	logger := clog.FromContext(ctx)
	r := initializeReport(c)

	matchChan, cancel := setupMatchHandling(ctx, c, logger, r)
	defer cancel()

	for _, scanPath := range c.ScanPaths {
		if c.Renderer != nil {
			c.Renderer.Scanning(ctx, scanPath)
    		}
		processedPath, cleanup, err := prepareScanPath(ctx, c, scanPath, logger)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			logger.Errorf("failed to prepare scan path %s: %v", scanPath, err)
			continue
		}

		err = processPaths(ctx, c, processedPath, logger, r, matchChan)
		if err != nil {
			return finalizeReport(c, r, err, matchChan)
		}
	}

	return finalizeReport(c, r, nil, matchChan)
}

// Initialize the report structure
func initializeReport(c malcontent.Config) *malcontent.Report {
	r := &malcontent.Report{Files: sync.Map{}}
	if len(c.IgnoreTags) > 0 {
		r.Filter = strings.Join(c.IgnoreTags, ",")
	}
	return r
}

// Setup match handling for early exits based on hits or misses
func setupMatchHandling(ctx context.Context, c malcontent.Config, logger *clog.Logger, r *malcontent.Report) (chan matchResult, context.CancelFunc) {
	matchChan := make(chan matchResult, 1)
	scanCtx, cancel := context.WithCancel(ctx)

	go func() {
		select {
		case match := <-matchChan:
			handleMatch(ctx, c, logger, r, match)
			cancel()
		case <-scanCtx.Done():
		}
	}()

	return matchChan, cancel
}

// Prepare the scan path (handle OCI images or plain paths)
func prepareScanPath(ctx context.Context, c malcontent.Config, scanPath string, logger *clog.Logger) (string, func(), error) {
	if c.OCI {
        // Store the original image URI for reference
        imageURI := scanPath

        // Extract the OCI image
        ociExtractPath, err := archive.OCI(ctx, imageURI)
        if err != nil {
            return "", nil, fmt.Errorf("failed to prepare OCI image for scanning: %w", err)
        }

        // Log debug information
        logger.Debug("OCI image prepared",
            slog.Any("scanPath", scanPath),
            slog.Any("ociExtractPath", ociExtractPath),
        )

        // Return the extracted path and a cleanup function
        return ociExtractPath, func() { os.RemoveAll(ociExtractPath) }, nil
    }

    // Non-OCI paths are returned as-is
    return scanPath, nil, nil

}

// Process paths (files or directories) concurrently
func processPaths(ctx context.Context, c malcontent.Config, scanPath string, logger *clog.Logger, r *malcontent.Report, matchChan chan matchResult) error {
	paths, err := findFilesRecursively(ctx, scanPath)
	if err != nil {
		return fmt.Errorf("find files: %w", err)
	}

	pc := make(chan string, len(paths))
	for _, path := range paths {
		pc <- path
	}
	close(pc)

	return processWithConcurrency(ctx, c, pc, logger, r, matchChan)
}

// Manage concurrency for processing paths
func processWithConcurrency(ctx context.Context, c malcontent.Config, pc chan string, logger *clog.Logger, r *malcontent.Report, matchChan chan matchResult) error {
	var g errgroup.Group
	g.SetLimit(maxConcurrency(c))

	for path := range pc {
		path := path // avoid closure capture
		g.Go(func() error {
			if programkind.IsSupportedArchive(path) {
				return handleArchive(ctx, c, path, logger, r, matchChan)
			}
			return processSingleFile(ctx, c, path, logger, r, matchChan)
		})
	}

	return g.Wait()
}

// Maximum concurrency setting
func maxConcurrency(c malcontent.Config) int {
	if c.Concurrency < 1 {
		return 1
	}
	return c.Concurrency
}

// Finalize the report, handle matches if any
func finalizeReport(c malcontent.Config, r *malcontent.Report, err error, matchChan chan matchResult) (*malcontent.Report, error) {
	select {
	case match := <-matchChan:
		if match.fr != nil {
			r.Files.Store(match.fr.Path, match.fr)
		}
		return r, match.err
	default:
		return r, err
	}
}

// Handle individual files
func processSingleFile(ctx context.Context, c malcontent.Config, path string, logger *clog.Logger, r *malcontent.Report, matchChan chan matchResult) error {
	fr, err := processFile(ctx, c, c.RuleFS, path, "", "", logger)
	if err != nil {
		r.Files.Store(path, &malcontent.FileReport{})
		return fmt.Errorf("process file: %w", err)
	}
	if fr == nil {
		return nil
	}

	storeFileReport(c, r, path, fr)
	handleExitFirst(ctx, c, path, fr, matchChan)
	return nil
}

// Handle archives
func handleArchive(ctx context.Context, c malcontent.Config, path string, logger *clog.Logger, r *malcontent.Report, matchChan chan matchResult) error {
	frs, err := processArchive(ctx, c, c.RuleFS, path, logger)
	if err != nil {
		logger.Errorf("unable to process archive %s: %v", path, err)
		return err
	}

	storeArchiveReports(c, r, frs)
	handleExitFirst(ctx, c, path, nil, matchChan)
	return nil
}

// Store individual file reports
func storeFileReport(c malcontent.Config, r *malcontent.Report, path string, fr *malcontent.FileReport) {
	if len(c.TrimPrefixes) > 0 {
		path = report.TrimPrefixes(path, c.TrimPrefixes)
	}
	r.Files.Store(path, fr)
}

// Store archive file reports
func storeArchiveReports(c malcontent.Config, r *malcontent.Report, frs *sync.Map) {
	frs.Range(func(key, value any) bool {
		if key == nil || value == nil {
			return true
		}
		if k, ok := key.(string); ok {
			if fr, ok := value.(*malcontent.FileReport); ok {
				r.Files.Store(k, fr)
			}
		}
		return true
	})
}

// Handle early exits on first hit/miss
func handleExitFirst(ctx context.Context, c malcontent.Config, path string, fr *malcontent.FileReport, matchChan chan matchResult) {
	if c.ExitFirstHit || c.ExitFirstMiss {
		var frMap sync.Map
		if fr != nil {
			frMap.Store(path, fr)
		}
		match, err := exitIfHitOrMiss(&frMap, path, c.ExitFirstHit, c.ExitFirstMiss)
		if err != nil {
			select {
			case matchChan <- matchResult{fr: match, err: err}:
			default:
			}
		}
	}
}

// Handle match rendering
func handleMatch(ctx context.Context, c malcontent.Config, logger *clog.Logger, r *malcontent.Report, match matchResult) {
	if match.fr != nil && c.Renderer != nil && match.fr.RiskScore >= c.MinFileRisk {
		if err := c.Renderer.File(ctx, match.fr); err != nil {
			logger.Errorf("render error: %v", err)
		}
	}
}

// processArchive extracts and scans a single archive file.
func processArchive(ctx context.Context, c malcontent.Config, rfs []fs.FS, archivePath string, logger *clog.Logger) (*sync.Map, error) {
	logger = logger.With("archivePath", archivePath)

	var err error
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

	for _, extractedFilePath := range extractedPaths {
		fr, err := processFile(ctx, c, rfs, extractedFilePath, archivePath, tmpRoot, logger)
		if err != nil {
			return nil, err
		}
		if fr != nil {
			// Store a clean reprepsentation of the archive's scanned file to match single file scanning behavior
			clean := strings.TrimPrefix(extractedFilePath, tmpRoot)
			frs.Store(clean, fr)
		}
	}

	return &frs, nil
}

// processFile scans a single output file, rendering live output if available.
func processFile(ctx context.Context, c malcontent.Config, ruleFS []fs.FS, path string, scanPath string, archiveRoot string, logger *clog.Logger) (*malcontent.FileReport, error) {
	logger = logger.With("path", path)

	fr, err := scanSinglePath(ctx, c, path, ruleFS, scanPath, archiveRoot)
	if err != nil {
		logger.Errorf("scan path: %v", err)
		return nil, err
	}

	if fr == nil {
		logger.Debugf("%s returned nil result", path)
		return nil, nil
	}

	if fr.Error != "" && c.Renderer.Name() != "Interactive" {
		logger.Errorf("scan error: %s", fr.Error)
		return nil, fmt.Errorf("report error: %v", fr.Error)
	}

	return fr, nil
}

// Scan YARA scans a data source, applying output filters if necessary.
func Scan(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	r, err := recursiveScan(ctx, c)
	if err != nil {
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
	if c.Stats {
		err = render.Statistics(&c, r)
		if err != nil {
			return r, fmt.Errorf("stats: %w", err)
		}
	}
	return r, nil
}
