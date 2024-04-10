// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/bincapz/rules"
	"github.com/chainguard-dev/clog"
	"github.com/hillu/go-yara/v4"
)

var FS = rules.FS

var skipFiles = map[string]bool{
	"third_party/Neo23x0/yara/configured_vulns_ext_vars.yar": true,
}

func Compile(ctx context.Context, root fs.FS, thirdParty bool) (*yara.Rules, error) {
	yc, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler: %w", err)
	}

	// used by 3rd party YARA rules
	vars := []string{"filepath", "filename", "extension", "filetype", "owner"}
	for _, v := range vars {
		if err := yc.DefineVariable(v, v); err != nil {
			return nil, err
		}
	}

	err = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		logger := clog.FromContext(ctx).With("path", path)
		if err != nil {
			return nil //nolint: nilerr // TODO: review this part
		}

		if !thirdParty && strings.Contains(path, "third_party") {
			logger.Info("skipping (third_party disabled)")
			return nil
		}

		if skipFiles[path] {
			logger.Info("skipping (skipFiles)")
			return nil
		}

		if !d.IsDir() && filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar" {
			logger.Info("reading")

			bs, err := fs.ReadFile(root, path)
			if err != nil {
				return fmt.Errorf("readfile: %w", err)
			}

			// Our Yara library likes to panic a lot
			defer func() {
				if err := recover(); err != nil {
					logger.Error("recovered from panic", slog.Any("error", err))
				}
			}()

			if err := yc.AddString(string(bs), path); err != nil {
				return fmt.Errorf("yara addfile %s: %w", path, err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	for _, ycw := range yc.Warnings {
		clog.WarnContext(ctx, "warning", slog.String("namespace", ycw.Rule.Namespace()), slog.String("warning", ycw.Text))
	}

	for _, yce := range yc.Errors {
		clog.ErrorContext(ctx, "errors", slog.String("namespace", yce.Rule.Namespace()), slog.String("error", yce.Text))
	}

	return yc.GetRules()
}
