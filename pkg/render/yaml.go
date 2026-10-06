// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bufio"
	"context"
	"io"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"gopkg.in/yaml.v3"
)

// yamlBufferSize is the size of the buffer between the YAML encoder, which
// writes in small pieces, and the output.
const yamlBufferSize = 64 << 10

// YAML writes the report as one YAML document: the bytes of
// yaml.Marshal(Report) and a newline. It streams the document to the output
// as it is encoded instead of building it in memory first.
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

	// Make the xsync.Map YAML-friendly. Without files, Files stays nil, which
	// is omitted just as an empty map is.
	yr := Report{Diff: rep.Diff}
	if rep.Files != nil {
		yr.Files = make(map[string]*malcontent.FileReport, rep.Files.Size())
		rep.Files.Range(func(key string, fr *malcontent.FileReport) bool {
			if ctx.Err() != nil {
				return false
			}
			sanitizeFileReport(key, fr, yr.Files)
			return true
		})
	}

	if c != nil && c.Stats && yr.Diff == nil {
		if s := serializedStats(c, rep); s != nil {
			yr.Stats = s
		}
	}

	bw := bufio.NewWriterSize(r.w, yamlBufferSize)
	enc := yaml.NewEncoder(bw)
	if err := enc.Encode(yr); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	// The encoder ends the document with a newline; the output has always
	// carried one more. bw keeps a write error, so Flush returns it.
	_ = bw.WriteByte('\n')
	return bw.Flush()
}
