// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/pkg/report"
	"github.com/chainguard-dev/clog"
	"github.com/hillu/go-yara/v4"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"golang.org/x/sync/errgroup"
)

// findFilesRecurslively returns a list of files found recursively within a path.
func findFilesRecursively(ctx context.Context, root string) ([]string, error) {
	clog.FromContext(ctx).Infof("finding files in %s ...", root)
	var files []string

	// Follow symlink if provided at the root
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}

	err = filepath.WalkDir(root,
		func(path string, info os.DirEntry, err error) error {
			if err != nil {
				clog.FromContext(ctx).Errorf("walk %s: %v", path, err)
				return err
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
func scanSinglePath(ctx context.Context, c bincapz.Config, yrs *yara.Rules, path string, absPath string, archiveRoot string) (*bincapz.FileReport, error) {
	logger := clog.FromContext(ctx)
	var mrs yara.MatchRules
	logger = logger.With("path", path)
	kind := programKind(ctx, path)
	logger = logger.With("kind", kind)
	logger.Info("scanning")
	if !c.IncludeDataFiles && kind == "" {
		//		logger.Info("not a program")
		return &bincapz.FileReport{Skipped: "data file", Path: path}, nil
	}

	logger.Debug("calling YARA ScanFile")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fd := f.Fd()
	if err := yrs.ScanFileDescriptor(fd, 0, 0, &mrs); err != nil {
		logger.Info("skipping", slog.Any("error", err))
		return &bincapz.FileReport{Path: path, Error: fmt.Sprintf("scanfile: %v", err)}, nil
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
		return &bincapz.FileReport{Path: path}, nil
	}

	return &fr, nil
}

// isSupportedArchive returns whether a path can be processed by our archive extractor.
func isSupportedArchive(path string) bool {
	return archiveMap[getExt(path)]
}

// errIfMatch generates the right error if a match is encountered.
func errIfHitOrMiss(frs map[string]*bincapz.FileReport, kind string, scanPath string, errIfHit bool, errIfMiss bool) error {
	bMap := map[string]bool{}
	count := 0
	for _, fr := range frs {
		for _, b := range fr.Behaviors {
			count++
			bMap[b.ID] = true
		}
	}

	bList := []string{}
	for b := range bMap {
		bList = append(bList, b)
	}
	sort.Strings(bList)

	suffix := ""
	if len(bList) > 0 {
		suffix = fmt.Sprintf(": %s", strings.Join(bList, " "))
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

// structs and types for sorting reports alphabetically by path
// kv stores the keys and values of a map.
type kv struct {
	key   string
	value *bincapz.FileReport
}

// reports is a slice of paths and their respective file reports.
type reports []kv

// Implement interfaces required for Sorting.
func (r reports) Len() int {
	return len(r)
}

func (r reports) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r reports) Less(i, j int) bool {
	return r[i].key < r[j].key
}

// recursiveScan recursively YARA scans the configured paths - handling archives and OCI images.
func recursiveScan(ctx context.Context, c bincapz.Config) (*bincapz.Report, error) {
	logger := clog.FromContext(ctx)
	logger.Debug("recursive scan", slog.Any("config", c))
	r := &bincapz.Report{
		Files: orderedmap.New[string, *bincapz.FileReport](),
	}
	if len(c.IgnoreTags) > 0 {
		r.Filter = strings.Join(c.IgnoreTags, ",")
	}

	if c.Rules == nil {
		return nil, fmt.Errorf("rules have not been loaded")
	}

	yrs := c.Rules
	logger.Infof("%d rules loaded", len(yrs.GetRules()))

	scanPathFindings := map[string]*bincapz.FileReport{}

	var pairs reports
	for _, scanPath := range c.ScanPaths {
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
			return nil, fmt.Errorf("find files: %w", err)
		}
		logger.Debug("files found", slog.Any("path count", len(paths)), slog.Any("scanPath", scanPath))

		maxConcurrency := c.Concurrency
		if maxConcurrency < 1 {
			maxConcurrency = 1
		} else if maxConcurrency > len(paths) {
			maxConcurrency = len(paths)
		}

		// path refers to a real local path, not the requested scanPath
		pc := make(chan string, len(paths))
		for _, path := range paths {
			pc <- path
		}
		close(pc)

		type findings struct {
			path string
			fr   *bincapz.FileReport
		}
		var result []findings
		var mu sync.Mutex
		process := func(path string) error {
			//nolint:nestif // ignore complexity of 13
			if isSupportedArchive(path) {
				logger.Debug("found archive path", slog.Any("path", path))
				frs, err := processArchive(ctx, c, yrs, path, logger)
				if err != nil {
					logger.Errorf("unable to process %s: %v", path, err)
				}

				// If we're handling an archive within an OCI archive, wait to for other files to declare a miss
				if !c.OCI {
					if err := errIfHitOrMiss(frs, "archive", path, c.ErrFirstHit, c.ErrFirstMiss); err != nil {
						mu.Lock()
						result = append(result, findings{path: path, fr: &bincapz.FileReport{}})
						mu.Unlock()
						return err
					}
				}

				for extractedPath, fr := range frs {
					mu.Lock()
					result = append(result, findings{path: extractedPath, fr: fr})
					mu.Unlock()
				}
			} else {
				trimPath := ""
				if c.OCI {
					scanPath = imageURI
					trimPath = ociExtractPath
				}

				logger.Debug("processing path", slog.Any("path", path))
				fr, err := processFile(ctx, c, yrs, path, scanPath, trimPath, logger)
				if err != nil {
					mu.Lock()
					result = append(result, findings{path: path, fr: &bincapz.FileReport{}})
					mu.Unlock()
					return err
				}
				if fr != nil {
					mu.Lock()
					result = append(result, findings{path: path, fr: fr})
					mu.Unlock()
					if !c.OCI {
						if err := errIfHitOrMiss(map[string]*bincapz.FileReport{path: fr}, "file", path, c.ErrFirstHit, c.ErrFirstMiss); err != nil {
							logger.Debugf("match short circuit: %s", err)
							mu.Lock()
							result = append(result, findings{path: path, fr: &bincapz.FileReport{}})
							mu.Unlock()
						}
					}
				}
			}
			return nil
		}

		var g errgroup.Group
		g.SetLimit(maxConcurrency)
		for path := range pc {
			path := path
			g.Go(func() error {
				return process(path)
			})
		}

		if err := g.Wait(); err != nil {
			logger.Errorf("error with processing %v\n", err)
		}

		for _, r := range result {
			scanPathFindings[r.path] = r.fr
		}

		// OCI images hadle their match his/miss logic per scanPath
		if c.OCI {
			if err := errIfHitOrMiss(scanPathFindings, "image", imageURI, c.ErrFirstHit, c.ErrFirstMiss); err != nil {
				return r, err
			}

			if err := os.RemoveAll(ociExtractPath); err != nil {
				logger.Errorf("remove %s: %v", scanPath, err)
			}
		}

		// Ensure that the report files are always sorted by path alphabetically
		insertSorted := func(key string, value *bincapz.FileReport) {
			pairs = append(pairs, kv{key: key, value: value})
			sort.Sort(pairs)
		}
		for path, fr := range scanPathFindings {
			insertSorted(path, fr)
		}

		// Add the sorted paths and file reports to the parent report and render the results
		for _, e := range pairs {
			r.Files.Set(e.key, e.value)
			if c.Renderer != nil && r.Diff == nil {
				if e.value.RiskScore < c.MinFileRisk {
					return nil, nil
				}

				if err := c.Renderer.File(ctx, e.value); err != nil {
					return nil, fmt.Errorf("render: %w", err)
				}
			}
		}
	} // loop: next scan path
	logger.Debugf("recursive scan complete: %d files", r.Files.Len())
	return r, nil
}

// processArchive extracts and scans a single archive file.
func processArchive(ctx context.Context, c bincapz.Config, yrs *yara.Rules, archivePath string, logger *clog.Logger) (map[string]*bincapz.FileReport, error) {
	logger = logger.With("archivePath", archivePath)

	var err error
	frs := map[string]*bincapz.FileReport{}

	tmpRoot, err := extractArchiveToTempDir(ctx, archivePath)
	if err != nil {
		return nil, fmt.Errorf("extract to temp: %w", err)
	}

	extractedPaths, err := findFilesRecursively(ctx, tmpRoot)
	if err != nil {
		return nil, fmt.Errorf("find files: %w", err)
	}

	for _, extractedFilePath := range extractedPaths {
		fr, err := processFile(ctx, c, yrs, extractedFilePath, archivePath, tmpRoot, logger)
		if err != nil {
			return nil, err
		}
		if fr != nil {
			frs[extractedFilePath] = fr
		}
	}
	if err := os.RemoveAll(tmpRoot); err != nil {
		logger.Errorf("remove %s: %v", tmpRoot, err)
	}

	return frs, nil
}

// processFile scans a single output file, rendering live output if available.
func processFile(ctx context.Context, c bincapz.Config, yrs *yara.Rules, path string, scanPath string, archiveRoot string, logger *clog.Logger) (*bincapz.FileReport, error) {
	logger = logger.With("path", path)

	fr, err := scanSinglePath(ctx, c, yrs, path, scanPath, archiveRoot)
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
func Scan(ctx context.Context, c bincapz.Config) (*bincapz.Report, error) {
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
