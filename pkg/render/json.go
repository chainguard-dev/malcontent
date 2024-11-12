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

func (r JSON) Scanning(_ context.Context, _ string) {}

func (r JSON) File(_ context.Context, _ *malcontent.FileReport) error {
	return nil
}

func (r JSON) Full(_ context.Context, rep *malcontent.Report) error {
	// Make the sync.Map JSON-friendly
	type jsonReport struct {
		Diff   *malcontent.DiffReport            `json:",omitempty" yaml:",omitempty"`
		Files  map[string]*malcontent.FileReport `json:",omitempty" yaml:",omitempty"`
		Filter string                            `json:",omitempty" yaml:",omitempty"`
	}

	jr := jsonReport{
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
				jr.Files[path] = r
			}
		}
		return true
	})

	j, err := json.MarshalIndent(jr, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", j)
	return err
}
