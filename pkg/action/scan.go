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
			logger.Infof("symlink target does not exist: %s", err.Error())
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
		logger.Infof("skipping %s [%s]: data file or empty", path, mime)
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
		logger.Info("skipping", slog.Any("error", err))
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

// recursiveScan recursively YARA scans the configured paths - handling archives and OCI images.
//
//nolint:gocognit,cyclop,nestif // ignoring complexity of 101,38
func recursiveScan(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	logger := clog.FromContext(ctx)
	r := &malcontent.Report{
		Files: sync.Map{},
	}
	if len(c.IgnoreTags) > 0 {
		r.Filter = strings.Join(c.IgnoreTags, ",")
	}

	// Store the first hit or miss result
	type matchResult struct {
		fr  *malcontent.FileReport
		err error
	}
	matchChan := make(chan matchResult, 1)
	var matchOnce sync.Once

	for _, scanPath := range c.ScanPaths {
		if c.Renderer != nil {
			c.Renderer.Scanning(ctx, scanPath)
		}
		imageURI := ""
		ociExtractPath := ""
		var err error

		if c.OCI {
			// store the image URI for later use
			imageURI = scanPath
			ociExtractPath, err = oci(ctx, imageURI)
			logger.Debug("oci image", slog.Any("scanPath", scanPath), slog.Any("ociExtractPath", ociExtractPath))
			if err != nil {
				return nil, fmt.Errorf("failed to prepare OCI image for scanning: %w", err)
			}
			scanPath = ociExtractPath
		}

		paths, err := findFilesRecursively(ctx, scanPath)
		if err != nil {
			if len(c.ScanPaths) == 1 {
				return nil, fmt.Errorf("find: %w", err)
			}
			// try to scan remaining scan paths
			logger.Errorf("find failed: %v", err)
			continue
		}

		maxConcurrency := c.Concurrency
		if maxConcurrency < 1 {
			maxConcurrency = 1
		}

		// path refers to a real local path, not the requested scanPath
		pc := make(chan string, len(paths))
		for _, path := range paths {
			pc <- path
		}
		close(pc)

		handleArchive := func(path string) error {
			frs, err := processArchive(ctx, c, c.RuleFS, path, logger)
			if err != nil {
				logger.Errorf("unable to process %s: %v", path, err)
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

		handleFile := func(path string) error {
			trimPath := ""
			if c.OCI {
				scanPath = imageURI
				trimPath = ociExtractPath
			}

			fr, err := processFile(ctx, c, c.RuleFS, path, scanPath, trimPath, logger)
			if err != nil {
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

		scanCtx, cancel := context.WithCancel(ctx)
		var g errgroup.Group
		g.SetLimit(maxConcurrency)

		// Poll the match channel for the first hit or miss
		go func() {
			select {
			case match := <-matchChan:
				if match.fr != nil && c.Renderer != nil && match.fr.RiskScore >= c.MinFileRisk {
					if err := c.Renderer.File(ctx, match.fr); err != nil {
						logger.Errorf("render error: %v", err)
					}
				}
				cancel()
			case <-scanCtx.Done():
				return
			}
		}()

		for path := range pc {
			g.Go(func() error {
				select {
				case <-scanCtx.Done():
					return scanCtx.Err()
				default:
					if isSupportedArchive(path) {
						return handleArchive(path)
					}
					return handleFile(path)
				}
			})
		}

		if err := g.Wait(); err != nil {
			if c.OCI {
				if cleanErr := os.RemoveAll(ociExtractPath); cleanErr != nil {
					logger.Errorf("remove %s: %v", scanPath, cleanErr)
				}
			}

			select {
			case match := <-matchChan:
				r := &malcontent.Report{
					Files: sync.Map{},
				}
				if match.fr != nil {
					if len(c.TrimPrefixes) > 0 {
						match.fr.Path = report.TrimPrefixes(match.fr.Path, c.TrimPrefixes)
					}
					r.Files.Store(match.fr.Path, match.fr)
				}
				return r, match.err
			default:
				return r, err
			}
		}

		// OCI images hadle their match his/miss logic per scanPath
		if c.OCI {
			match, err := exitIfHitOrMiss(&r.Files, imageURI, c.ExitFirstHit, c.ExitFirstMiss)
			if err != nil && c.Renderer != nil && match.RiskScore >= c.MinFileRisk {
				if match != nil && c.Renderer != nil && match.RiskScore >= c.MinFileRisk {
					if renderErr := c.Renderer.File(ctx, match); renderErr != nil {
						logger.Errorf("render error: %v", renderErr)
					}
				}
				cancel()
				return r, err
			}

			if err := os.RemoveAll(ociExtractPath); err != nil {
				logger.Errorf("remove %s: %v", scanPath, err)
			}
		}
		cancel()
	} // loop: next scan path
	return r, nil
}

// processArchive extracts and scans a single archive file.
func processArchive(ctx context.Context, c malcontent.Config, rfs []fs.FS, archivePath string, logger *clog.Logger) (*sync.Map, error) {
	logger = logger.With("archivePath", archivePath)

	var err error
	var frs sync.Map

	tmpRoot, err := extractArchiveToTempDir(ctx, archivePath)
	if err != nil {
		return nil, fmt.Errorf("extract to temp: %w", err)
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
			extractedFilePath = strings.TrimPrefix(extractedFilePath, tmpRoot)
			frs.Store(extractedFilePath, fr)
		}
	}
	if err := os.RemoveAll(tmpRoot); err != nil {
		logger.Errorf("remove %s: %v", tmpRoot, err)
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
		logger.Infof("%s returned nil result", path)
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
