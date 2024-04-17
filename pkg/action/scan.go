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

var archiveExtensions = []string{".apk", ".jar", ".tar", ".tar.gz", ".tar.xz", ".zip"}

// return a list of files within a path.
func findFilesRecursively(ctx context.Context, root string) ([]string, error) {
	clog.FromContext(ctx).Infof("finding files in %s ...", root)
	files := []string{}

	err := filepath.Walk(root,
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
			files = append(files, path)
			return nil
		})
	return files, err
}

func scanSinglePath(ctx context.Context, c Config, yrs *yara.Rules, path string) (*bincapz.FileReport, error) {
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

	if len(fr.Behaviors) == 0 && c.OmitEmpty {
		return nil, nil
	}

	return &fr, nil
}

func recursiveScan(ctx context.Context, c Config) (*bincapz.Report, error) {
	logger := clog.FromContext(ctx)
	logger.Debug("scan", slog.Any("config", c))
	r := &bincapz.Report{
		Files: map[string]bincapz.FileReport{},
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
		if c.OCI {
			var err error
			sp, err = oci(sp)
			if err != nil {
				return nil, fmt.Errorf("failed to prepare OCI image for scanning: %w", err)
			}
		}
		var isArchive bool
		for _, ext := range archiveExtensions {
			if strings.HasSuffix(sp, ext) {
				isArchive = true
				break
			}
		}
		if isArchive {
			var err error
			sp, err = archive(sp)
			if err != nil {
				return nil, fmt.Errorf("failed to prepare archive for scanning: %w", err)
			}
		}
		rp, err := findFilesRecursively(ctx, sp)
		if err != nil {
			return nil, fmt.Errorf("find files: %w", err)
		}
		for _, p := range rp {
			fr, err := scanSinglePath(ctx, c, yrs, p)
			if err != nil {
				logger.Errorf("scan path: %v", err)
				continue
			}
			if fr == nil {
				continue
			}
			if c.Renderer != nil {
				if fr.RiskScore < c.MinFileScore {
					continue
				}
				if err := c.Renderer.File(ctx, *fr); err != nil {
					return r, fmt.Errorf("render: %w", err)
				}
			}
			r.Files[p] = *fr
		}
		if c.OCI || isArchive {
			if err := os.RemoveAll(sp); err != nil {
				logger.Errorf("remove %s: %v", sp, err)
			}
		}
	}

	return r, nil
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
