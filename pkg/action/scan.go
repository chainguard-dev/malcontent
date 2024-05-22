// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	files := []string{}

	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("abs: %w", err)
	}

	err = filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				clog.FromContext(ctx).Errorf("walk %s: %v", path, err)
				return err
			}
			if info.IsDir() {
				return nil
			}
			// False positives in refs file
			if strings.Contains(path, "/.git/") {
				return nil
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}

			if c.IgnoreSelf && abs == self {
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

func scanSinglePath(ctx context.Context, c Config, yrs *yara.Rules, path string, absPath string, root string) (*bincapz.FileReport, error) {
	logger := clog.FromContext(ctx)
	var mrs yara.MatchRules
	logger = logger.With("path", path)
	kind := programKind(ctx, path)
	logger = logger.With("kind", kind)
	logger.Info("scanning")
	if !c.IncludeDataFiles && kind == "" {
		logger.Info("not a program")
		return &bincapz.FileReport{Skipped: "data file"}, nil
	}

	if err := yrs.ScanFile(path, 0, 0, &mrs); err != nil {
		logger.Info("skipping", slog.Any("error", err))
		return &bincapz.FileReport{Path: path, Error: fmt.Sprintf("scanfile: %v", err)}, nil
	}

	fr, err := report.Generate(ctx, path, mrs, c.IgnoreTags, c.MinResultScore)
	if err != nil {
		return nil, err
	}

	// If absPath is provided, use it instead of the path if they are different.
	// This is useful when scanning images and archives.
	if absPath != "" && absPath != path && root != "" {
		fr.Path = fmt.Sprintf("%s ∴ %s", absPath, formatPath(cleanPath(path, root)))
	}

	if len(fr.Behaviors) == 0 && c.OmitEmpty {
		return nil, nil
	}

	return &fr, nil
}

func recursiveScan(ctx context.Context, c Config) (*bincapz.Report, error) {
	logger := clog.FromContext(ctx)
	logger.Debug("scan", slog.Any("config", c))
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

	for _, sp := range c.ScanPaths {
		var ip string
		if c.OCI {
			var err error
			// store the image URI for later use
			ip = sp
			sp, err = oci(ctx, sp)
			if err != nil {
				return nil, fmt.Errorf("failed to prepare OCI image for scanning: %w", err)
			}
		}

		rp, err := findFilesRecursively(ctx, sp, c)
		if err != nil {
			return nil, fmt.Errorf("find files: %w", err)
		}

		for _, p := range rp {
			isArchive := false
			ext := getExt(p)
			if _, ok := archiveMap[ext]; ok {
				isArchive = true
			}
			if isArchive {
				err = processArchive(ctx, c, yrs, r, p, logger)
				if err != nil {
					logger.Errorf("unable to process %s: %v", p, err)
				}
			} else {
				if c.OCI {
					sp = ip
				}
				err = processFile(ctx, c, yrs, r, p, sp, "", logger)
				if err != nil {
					logger.Errorf("unable to process %s: %v", p, err)
				}
			}
		}
		if c.OCI {
			if err := os.RemoveAll(sp); err != nil {
				logger.Errorf("remove %s: %v", sp, err)
			}
		}
	}

	return r, nil
}

func processArchive(ctx context.Context, c Config, yrs *yara.Rules, r *bincapz.Report, path string, logger *clog.Logger) error {
	var err error

	er, err := extractArchiveToTempDir(ctx, path)
	if err != nil {
		return fmt.Errorf("extract to temp: %w", err)
	}

	aps, err := findFilesRecursively(ctx, er, c)
	if err != nil {
		return fmt.Errorf("find files: %w", err)
	}

	for _, ap := range aps {
		err = processFile(ctx, c, yrs, r, ap, path, er, logger)
		if err != nil {
			return err
		}
	}
	if err := os.RemoveAll(er); err != nil {
		logger.Errorf("remove %s: %v", er, err)
	}
	return nil
}

func processFile(
	ctx context.Context,
	c Config, yrs *yara.Rules,
	r *bincapz.Report,
	path string,
	absPath string,
	ar string,
	logger *clog.Logger,
) error {
	fr, err := scanSinglePath(ctx, c, yrs, path, absPath, ar)
	if err != nil {
		logger.Errorf("scan path: %v", err)
		return nil
	}
	if fr == nil {
		return nil
	}

	if c.IgnoreSelf && fr.IsBincapz {
		clog.FromContext(ctx).Infof("dropping results for %s (it's bincapz)...", fr.Path)
		return nil
	}

	if c.Renderer != nil {
		if fr.RiskScore < c.MinFileScore {
			return nil
		}
		if err := c.Renderer.File(ctx, fr); err != nil {
			return fmt.Errorf("render: %w", err)
		}
	}
	r.Files[path] = fr
	return nil
}

func Scan(ctx context.Context, c Config) (*bincapz.Report, error) {
	r, err := recursiveScan(ctx, c)
	if err != nil {
		return r, err
	}
	for path, rf := range r.Files {
		if rf.RiskScore < c.MinFileScore {
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
