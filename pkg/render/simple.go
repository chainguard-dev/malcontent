// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

// Simple renders one line per behavior with a lowercase risk level. It is
// safe for concurrent use: each File call writes its output with a single
// Write.
type Simple struct {
	out blockWriter
}

func NewSimple(w io.Writer) *Simple {
	return &Simple{out: blockWriter{w: w}}
}

func (r *Simple) Name() string { return "Simple" }

func (r *Simple) Scanning(_ context.Context, _ string) {}

func (r *Simple) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr.Skipped != "" || len(fr.Behaviors) == 0 {
		return nil
	}

	b := getBuffer()
	defer putBuffer(b)

	b.WriteString("# ")
	b.WriteString(sanitizeTerminal(fr.Path))
	b.WriteString(": ")
	b.WriteString(lowerRisk(fr.RiskLevel))
	b.WriteByte('\n')

	for _, bh := range fr.Behaviors {
		b.WriteString(bh.ID)
		b.WriteString(": ")
		b.WriteString(lowerRisk(bh.RiskLevel))
		b.WriteByte('\n')
	}
	return r.out.write(b.Bytes())
}

// lowerRisk returns level in lowercase without allocating for the standard
// risk levels.
func lowerRisk(level string) string {
	switch level {
	case report.LevelCRITICAL:
		return "critical"
	case report.LevelHIGH:
		return "high"
	case report.LevelMEDIUM:
		return "medium"
	case report.LevelLOW:
		return "low"
	case report.LevelNONE:
		return "none"
	default:
		return strings.ToLower(level)
	}
}

func (r *Simple) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// guard against nil reports
	if rep == nil || rep.Diff == nil {
		return nil
	}

	b := getBuffer()
	defer putBuffer(b)

	for removed := rep.Diff.Removed.Oldest(); removed != nil; removed = removed.Next() {
		if len(removed.Value.Behaviors) == 0 {
			continue
		}

		b.WriteString("--- missing: ")
		b.WriteString(sanitizeTerminal(removed.Key))
		b.WriteByte('\n')

		for _, bh := range removed.Value.Behaviors {
			writeSimpleChange(b, '-', bh.ID)
		}
		if err := r.out.flush(b); err != nil {
			return err
		}
	}

	for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
		if len(added.Value.Behaviors) == 0 {
			continue
		}

		b.WriteString("+++ added: ")
		b.WriteString(sanitizeTerminal(added.Key))
		b.WriteByte('\n')

		for _, bh := range added.Value.Behaviors {
			writeSimpleChange(b, '+', bh.ID)
		}
		if err := r.out.flush(b); err != nil {
			return err
		}
	}

	count := func(bs []*malcontent.Behavior) (int, int) {
		var added, removed int
		for _, bh := range bs {
			if bh.DiffAdded {
				added++
			}
			if bh.DiffRemoved {
				removed++
			}
		}

		return added, removed
	}

	for modified := rep.Diff.Modified.Oldest(); modified != nil; modified = modified.Next() {
		added, removed := count(modified.Value.Behaviors)
		if added == 0 && removed == 0 {
			continue
		}

		if modified.Value.PreviousPath != "" {
			b.WriteString(">>> moved (")
			writeSimpleCounts(b, added, removed)
			b.WriteString(sanitizeTerminal(modified.Value.PreviousPath))
			b.WriteString(" -> ")
			b.WriteString(sanitizeTerminal(modified.Value.Path))
		} else {
			b.WriteString("*** changed (")
			writeSimpleCounts(b, added, removed)
			b.WriteString(sanitizeTerminal(modified.Value.Path))
		}
		b.WriteByte('\n')

		for _, bh := range modified.Value.Behaviors {
			if bh.DiffRemoved {
				writeSimpleChange(b, '-', bh.ID)
			}
			if bh.DiffAdded {
				writeSimpleChange(b, '+', bh.ID)
			}
		}
		if err := r.out.flush(b); err != nil {
			return err
		}
	}

	return nil
}

// writeSimpleCounts writes "<added> added, <removed> removed): ".
func writeSimpleCounts(b *bytes.Buffer, added, removed int) {
	b.Write(strconv.AppendInt(b.AvailableBuffer(), int64(added), 10))
	b.WriteString(" added, ")
	b.Write(strconv.AppendInt(b.AvailableBuffer(), int64(removed), 10))
	b.WriteString(" removed): ")
}

// writeSimpleChange writes a behavior ID marked added (+) or removed (-).
func writeSimpleChange(b *bytes.Buffer, mark byte, id string) {
	b.WriteByte(mark)
	b.WriteString(id)
	b.WriteByte('\n')
}
