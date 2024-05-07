// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"

	"github.com/chainguard-dev/bincapz/rules"
	"github.com/chainguard-dev/clog"
	"github.com/hillu/go-yara/v4"
)

var FS = rules.FS

func Recursive(ctx context.Context, fss []fs.FS) (*yara.Rules, error) {
	yc, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler: %w", err)
	}

	for _, root := range fss {
		err = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			logger := clog.FromContext(ctx).With("path", path)
			if !d.IsDir() && filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar" {
				bs, err := fs.ReadFile(root, path)
				if err != nil {
					return fmt.Errorf("readfile: %w", err)
				}

				// Our Yara library panics a lot
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
	}

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
