// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

type JSON struct {
	w io.Writer
}

func NewJSON(w io.Writer) JSON {
	return JSON{w: w}
}

func (r JSON) Name() string { return "JSON" }

func (r JSON) Scanning(_ context.Context, _ string) {}

func (r JSON) File(_ context.Context, _ *malcontent.FileReport) error {
	return nil
}

func (r JSON) Full(ctx context.Context, c *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	jr := Report{
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
					// Filter out diff-related fields
					r.ArchiveRoot = ""
					r.FullPath = ""
					jr.Files[path] = r
				}
			}
		}
		return true
	})

	if c != nil && c.Stats && jr.Diff == nil {
		jr.Stats = serializedStats(c, rep)
	}

	j, err := json.MarshalIndent(jr, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", j)
	return err
}
