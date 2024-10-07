// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/pkg/report"

	"github.com/hillu/go-yara/v4"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"golang.org/x/sync/errgroup"
)

var (
	// compiledRuleCache are a cache of previously compiled rules.
	compiledRuleCache *yara.Rules
	// compileOnce ensures that we compile rules only once even across threads.
	compileOnce sync.Once
)

// findFilesRecursively returns a list of files found recursively within a path.
func findFilesRecursively(ctx context.Context, rootPath string) ([]string, error) {
	clog.FromContext(ctx).Infof("finding files in %s ...", rootPath)
	var files []string

	// Follow symlink if provided at the root
	root, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
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
				return fmt.Errorf("walk: %w", err)
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
	kind := programKind(ctx, path)
	logger = logger.With("kind", kind)
	logger.Info("scanning")
	if !c.IncludeDataFiles && kind == "" {
		//		logger.Info("not a program")
		return &malcontent.FileReport{Skipped: "data file", Path: path}, nil
	}

	logger.Debug("calling YARA ScanFile")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fd := f.Fd()

	yrs, err := cachedRules(ctx, ruleFS)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if err := yrs.ScanFileDescriptor(fd, 0, 0, &mrs); err != nil {
		logger.Info("skipping", slog.Any("error", err))
		return &malcontent.FileReport{Path: path, Error: fmt.Sprintf("scan: %v", err)}, nil
	}

	fr, err := report.Generate(ctx, path, mrs, c, archiveRoot)
	if err != nil {
		return nil, err
	}

	// If absPath is provided, use it instead of the path if they are different.
	// This is useful when scanning images and archives.
	if absPath != "" && absPath != path && archiveRoot != "" {
		cleanPath, err := cleanPath(path, archiveRoot)
		if err != nil {
			return nil, err
		}
		fr.Path = fmt.Sprintf("%s ∴ %s", absPath, formatPath(cleanPath))
	}

	if len(fr.Behaviors) == 0 {
		return &malcontent.FileReport{Path: path}, nil
	}

	return &fr, nil
}

// isSupportedArchive returns whether a path can be processed by our archive extractor.
func isSupportedArchive(path string) bool {
	return archiveMap[getExt(path)]
}

// errIfMatch generates the right error if a match is encountered.
func errIfHitOrMiss(frs *sync.Map, kind string, scanPath string, errIfHit bool, errIfMiss bool) error {
	var (
		bList  []string
		bMap   sync.Map
		count  int
		suffix string
	)
	if frs != nil {
		frs.Range(func(_, value any) bool {
			if value == nil {
				return true
			}
			if fr, ok := value.(*malcontent.FileReport); ok {
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

		if len(bList) > 0 {
			suffix = fmt.Sprintf(": %s", strings.Join(bList, " "))
		}
	}

	// Behavioral note: this logic is per-archive or per-file, depending on context
	if errIfHit && count != 0 {
		return fmt.Errorf("%d matching capabilities in %s %s%s", count, scanPath, kind, suffix)
	}

	if errIfMiss && count == 0 {
		return fmt.Errorf("no matching capabilities in %s %s%s", scanPath, kind, suffix)
	}
	return nil
}

func cachedRules(ctx context.Context, fss []fs.FS) (*yara.Rules, error) {
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
//nolint:gocognit // ignoring complexity of 101 > 98
func recursiveScan(ctx context.Context, c malcontent.Config) (*malcontent.Report, error) {
	logger := clog.FromContext(ctx)
	logger.Debug("recursive scan", slog.Any("config", c))
	r := &malcontent.Report{
		Files: orderedmap.New[string, *malcontent.FileReport](),
	}
	if len(c.IgnoreTags) > 0 {
		r.Filter = strings.Join(c.IgnoreTags, ",")
	}

	var scanPathFindings sync.Map

	for _, scanPath := range c.ScanPaths {
		if c.Renderer != nil {
			c.Renderer.Scanning(ctx, scanPath)
		}
		logger.Debug("recursive scan", slog.Any("scanPath", scanPath))
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

		logger.Debug("files found", slog.Any("path count", len(paths)), slog.Any("scanPath", scanPath))

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
			logger.Debug("found archive path", slog.Any("path", path))
			frs, err := processArchive(ctx, c, c.RuleFS, path, logger)
			if err != nil {
				logger.Errorf("unable to process %s: %v", path, err)
			}
			// If we're handling an archive within an OCI archive, wait to for other files to declare a miss
			if !c.OCI {
				if err := errIfHitOrMiss(frs, "archive", path, c.ErrFirstHit, c.ErrFirstMiss); err != nil {
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
							scanPathFindings.Store(k, fr)
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

			logger.Debug("processing path", slog.Any("path", path))
			fr, err := processFile(ctx, c, c.RuleFS, path, scanPath, trimPath, logger)
			if err != nil {
				scanPathFindings.Store(path, &malcontent.FileReport{})
				return err
			}
			if fr != nil {
				scanPathFindings.Store(path, fr)
				if !c.OCI {
					var frMap sync.Map
					frMap.Store(path, fr)
					if err := errIfHitOrMiss(&frMap, "file", path, c.ErrFirstHit, c.ErrFirstMiss); err != nil {
						logger.Debugf("match short circuit: %s", err)
						scanPathFindings.Store(path, &malcontent.FileReport{})
					}
				}
			}
			return nil
		}
		var g errgroup.Group
		g.SetLimit(maxConcurrency)
		for path := range pc {
			g.Go(func() error {
				if isSupportedArchive(path) {
					return handleArchive(path)
				}
				return handleFile(path)
			})
		}

		if err := g.Wait(); err != nil {
			logger.Errorf("error with processing %v\n", err)
		}

		var pathKeys []string
		scanPathFindings.Range(func(key, _ interface{}) bool {
			if key == nil {
				return true
			}
			if k, ok := key.(string); ok {
				pathKeys = append(pathKeys, k)
			}
			return true
		})
		slices.Sort(pathKeys)

		// OCI images hadle their match his/miss logic per scanPath
		if c.OCI {
			if err := errIfHitOrMiss(&scanPathFindings, "image", imageURI, c.ErrFirstHit, c.ErrFirstMiss); err != nil {
				return r, err
			}

			if err := os.RemoveAll(ociExtractPath); err != nil {
				logger.Errorf("remove %s: %v", scanPath, err)
			}
		}

		// Add the sorted paths and file reports to the parent report and render the results
		for _, k := range pathKeys {
			finding, ok := scanPathFindings.LoadAndDelete(k)
			if !ok {
				return nil, fmt.Errorf("could not load finding from sync map")
			}
			if fr, ok := finding.(*malcontent.FileReport); ok {
				r.Files.Set(k, fr)
				if c.Renderer != nil && r.Diff == nil {
					if fr.RiskScore < c.MinFileRisk {
						continue
					}
					if err := c.Renderer.File(ctx, fr); err != nil {
						return nil, fmt.Errorf("render: %w", err)
					}
				}
			}
		}
	} // loop: next scan path
	logger.Debugf("recursive scan complete: %d files", r.Files.Len())
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

	if fr.Error != "" {
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
	for files := r.Files.Oldest(); files != nil; files = files.Next() {
		if files.Value.RiskScore < c.MinFileRisk {
			r.Files.Delete(files.Key)
		}
	}
	if c.Stats {
		err = render.Statistics(r)
		if err != nil {
			return r, err
		}
	}
	return r, nil
}
