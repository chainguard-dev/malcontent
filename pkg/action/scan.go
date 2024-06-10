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

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/pkg/report"
	"github.com/chainguard-dev/clog"
	"github.com/hillu/go-yara/v4"
)

// return a list of files within a path.
func findFilesRecursively(ctx context.Context, root string, c Config) ([]string, error) {
	clog.FromContext(ctx).Infof("finding files in %s ...", root)
	var files []string

	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("abs: %w", err)
	}

	// Follow symlink if provided at the root
	root, err = filepath.EvalSymlinks(root)
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

			if c.IgnoreSelf && path == self {
				clog.FromContext(ctx).Infof("skipping %s (self)", path)
				return nil
			}
			files = append(files, path)

			return nil
		})
	return files, err
}

// cleanPath removes the temporary directory prefix from the path.
func cleanPath(path string, prefix string) string {
	return strings.TrimPrefix(path, prefix)
}

// formatPath formats the path for display.
func formatPath(path string) string {
	if strings.Contains(path, "\\") {
		path = strings.ReplaceAll(path, "\\", "/")
	}
	return strings.TrimPrefix(path, "/")
}

func scanSinglePath(ctx context.Context, c Config, yrs *yara.Rules, path string, absPath string, archiveRoot string) (*bincapz.FileReport, error) {
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
	if err := yrs.ScanFile(path, 0, 0, &mrs); err != nil {
		logger.Info("skipping", slog.Any("error", err))
		return &bincapz.FileReport{Path: path, Error: fmt.Sprintf("scanfile: %v", err)}, nil
	}

	fr, err := report.Generate(ctx, path, mrs, c.IgnoreTags, c.MinRisk)
	if err != nil {
		return nil, err
	}

	// If absPath is provided, use it instead of the path if they are different.
	// This is useful when scanning images and archives.
	if absPath != "" && absPath != path && archiveRoot != "" {
		fr.Path = fmt.Sprintf("%s ∴ %s", absPath, formatPath(cleanPath(path, archiveRoot)))
	}

	if len(fr.Behaviors) == 0 && c.OmitEmpty {
		return nil, nil
	}

	return &fr, nil
}

// isSupportedArchive returns whether a path can be processed by our archive extractor
func isSupportedArchive(path string) bool {
	return archiveMap[getExt(path)]
}

// errIfMatch generates the right error if a match is encountered
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

func recursiveScan(ctx context.Context, c Config) (*bincapz.Report, error) {
	logger := clog.FromContext(ctx)
	logger.Debug("recursive scan", slog.Any("config", c))
	r := &bincapz.Report{
		Files: map[string]*bincapz.FileReport{},
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

	for _, scanPath := range c.ScanPaths {
		logger.Debug("recursive scan", slog.Any("scanPath", scanPath))
		imageURI := ""
		var err error

		if c.OCI {
			// store the image URI for later use
			imageURI = scanPath
			ociExtractPath, err := oci(ctx, imageURI)
			logger.Debug("oci image", slog.Any("scanPath", scanPath), slog.Any("ociExtractPath", ociExtractPath))
			if err != nil {
				return nil, fmt.Errorf("failed to prepare OCI image for scanning: %w", err)
			}
			scanPath = ociExtractPath
			defer func() {
				if err := os.RemoveAll(ociExtractPath); err != nil {
					logger.Errorf("remove %s: %v", scanPath, err)
				}
			}()
		}

		paths, err := findFilesRecursively(ctx, scanPath, c)
		if err != nil {
			return nil, fmt.Errorf("find files: %w", err)
		}
		logger.Debug("files found", slog.Any("path count", len(paths)), slog.Any("scanPath", scanPath))

		// path refersll to a real local path, not a virtual scan path
		for _, path := range paths {
			if isSupportedArchive(path) {
				logger.Debug("found archive path", slog.Any("path", path))
				frs, err := processArchive(ctx, c, yrs, path, logger)
				if err != nil {
					logger.Errorf("unable to process %s: %v", path, err)
				}

				// If we're handling an archive within an OCI archive, wait to for other files to declare a miss
				if !c.OCI {
					if err := errIfHitOrMiss(frs, "archive", path, c.ErrFirstHit, c.ErrFirstMiss); err != nil {
						logger.Debugf("match short circuit: %v", err)
						return r, err
					}
				}

				for extractedPath, fr := range frs {
					scanPathFindings[extractedPath] = fr
				}
				continue
			}

			if c.OCI {
				scanPath = imageURI
			}

			logger.Debug("processing path path", slog.Any("path", path))
			fr, err := processFile(ctx, c, yrs, path, scanPath, "", logger)
			if err != nil {
				return r, err
			}
			if fr == nil {
				continue
			}
			scanPathFindings[path] = fr
			if !c.OCI {
				if err := errIfHitOrMiss(map[string]*bincapz.FileReport{path: fr}, "file", path, c.ErrFirstHit, c.ErrFirstMiss); err != nil {
					logger.Debugf("match short circuit: %s", err)
					return r, err
				}
			}
		}

		// OCI images hadle their match his/miss logic per scanPath
		if c.OCI {
			if err := errIfHitOrMiss(scanPathFindings, "image", imageURI, c.ErrFirstHit, c.ErrFirstMiss); err != nil {
				return r, err
			}
		}

		for path, fr := range scanPathFindings {
			r.Files[path] = fr
		}
	}

	logger.Debugf("recursive scan complete: %d files", len(r.Files))
	return r, nil
}

func processArchive(ctx context.Context, c Config, yrs *yara.Rules, archivePath string, logger *clog.Logger) (map[string]*bincapz.FileReport, error) {
	logger = logger.With("archivePath", archivePath)

	var err error
	frs := map[string]*bincapz.FileReport{}

	tmpRoot, err := extractArchiveToTempDir(ctx, archivePath)
	if err != nil {
		return nil, fmt.Errorf("extract to temp: %w", err)
	}

	extractedPaths, err := findFilesRecursively(ctx, tmpRoot, c)
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

func processFile(ctx context.Context, c Config, yrs *yara.Rules, path string, scanPath string, archiveRoot string, logger *clog.Logger) (*bincapz.FileReport, error) {
	logger = logger.With("path", path)

	fr, err := scanSinglePath(ctx, c, yrs, path, scanPath, archiveRoot)
	if err != nil {
		logger.Errorf("scan path: %v", err)
		return nil, nil
	}
	if fr.Error != "" {
		logger.Debugf("scan error: %s", fr.Error)
		return nil, nil
	}

	if fr == nil {
		logger.Infof("%s returned nil result", path)
		return nil, nil
	}

	if c.IgnoreSelf && fr.IsBincapz {
		clog.FromContext(ctx).Infof("dropping results for %s (it's bincapz)...", fr.Path)
		return nil, nil
	}

	if c.Renderer != nil {
		if fr.RiskScore < c.MinFileRisk {
			// logger.Infof("%s [%d] does not meet min file risk [%d]", path, fr.RiskScore, c.MinFileRisk)
			return nil, nil
		}

		if err := c.Renderer.File(ctx, fr); err != nil {
			return nil, fmt.Errorf("render: %w", err)
		}
	}

	return fr, nil
}

func Scan(ctx context.Context, c Config) (*bincapz.Report, error) {
	r, err := recursiveScan(ctx, c)
	if err != nil {
		return r, err
	}
	for path, rf := range r.Files {
		if rf.RiskScore < c.MinFileRisk {
			delete(r.Files, path)
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
