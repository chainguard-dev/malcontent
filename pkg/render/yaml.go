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

func (r YAML) Scanning(_ context.Context, _ string) {}

func (r YAML) File(_ context.Context, _ *malcontent.FileReport) error {
	return nil
}

func (r YAML) Full(_ context.Context, rep *malcontent.Report) error {
	// Make the sync.Map YAML-friendly
	yr := RenderReport{
		Diff:   rep.Diff,
		Files:  make(map[string]*malcontent.FileReport),
		Filter: "",
	}

	rep.Files.Range(func(key, value any) bool {
		if key == nil || value == nil {
			return true
		}
		if path, ok := key.(string); ok {
			if r, ok := value.(*malcontent.FileReport); ok {
				if r.Skipped == "" {
					yr.Files[path] = r
				}
			}
		}
		return true
	})

	yaml, err := yaml.Marshal(yr)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", yaml)
	return err
}
