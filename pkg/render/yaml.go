// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"gopkg.in/yaml.v3"
)

type YAML struct {
	w io.Writer
}

func NewYAML(w io.Writer) YAML {
	return YAML{w: w}
}

func (r YAML) Name() string { return "YAML" }

func (r YAML) Scanning(_ context.Context, _ string) {}

func (r YAML) File(_ context.Context, _ *malcontent.FileReport) error {
	return nil
}

func (r YAML) Full(ctx context.Context, c *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// guard against nil reports
	if rep == nil {
		return nil
	}

	// Make the sync.Map YAML-friendly
	yr := Report{
		Diff:   rep.Diff,
		Files:  make(map[string]*malcontent.FileReport),
		Filter: "",
	}

	rep.Files.Range(func(key, value any) bool {
		if ctx.Err() != nil {
			return false
		}
		if key == nil || value == nil {
			return true
		}
		if path, ok := key.(string); ok {
			if r, ok := value.(*malcontent.FileReport); ok {
				if r.Skipped == "" {
					r.ArchiveRoot = ""
					r.FullPath = ""
					yr.Files[path] = r
				}
			}
		}
		return true
	})

	if c != nil && c.Stats && yr.Diff == nil {
		if s := serializedStats(c, rep); s != nil {
			yr.Stats = s
		}
	}

	yaml, err := yaml.Marshal(yr)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", yaml)
	return err
}
