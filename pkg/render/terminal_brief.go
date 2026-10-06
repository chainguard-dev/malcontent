// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Terminal Brief renderer
//
// Example:
//
// [CRITICAL] /bin/ls: frobber (whatever), xavier (whatever)
// [HIGH    ] /bin/zxa:
// [MED     ] /bin/ar:

package render

import (
	"context"
	"fmt"
	"io"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// briefLinePrefix starts each behavior line and wrapped evidence line.
const briefLinePrefix = "│     "

// TerminalBrief renders one line per behavior as the scan reports each file.
// It is safe for concurrent use: each File call writes its output with a
// single Write.
type TerminalBrief struct {
	out blockWriter
	// width is the terminal width that long evidence wraps against, measured once.
	width int
}

func NewTerminalBrief(w io.Writer) *TerminalBrief {
	return &TerminalBrief{out: blockWriter{w: w}, width: suggestedWidth()}
}

func (r *TerminalBrief) Name() string { return "TerminalBrief" }

func (r *TerminalBrief) Scanning(_ context.Context, path string) {
	r.out.scanning(path)
}

func (r *TerminalBrief) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr.Skipped != "" || len(fr.Behaviors) == 0 {
		return nil
	}

	p := currentPalette()
	rs := p.risk(fr.RiskLevel)
	ev := p.evidence
	b := getBuffer()
	defer putBuffer(b)

	writeSummaryHeader(b, fr.RiskScore)
	b.WriteString(sanitizeTerminal(fr.Path))
	b.WriteByte('\n')

	for _, bh := range fr.Behaviors {
		start := b.Len()
		b.WriteString(briefLinePrefix)
		rs.wrap(b, "•")
		b.WriteByte(' ')
		rs.wrap(b, bh.ID)
		b.WriteString(" — ")
		b.WriteString(bh.Description)
		end := b.Len()

		e := sanitizeTerminal(evidenceString(bh.MatchStrings, bh.Description))

		// no evidence to give
		if e == "" {
			b.WriteByte('\n')
			continue
		}

		b.WriteString(p.hiBlack.on)
		b.WriteByte(':')
		b.WriteString(p.hiBlack.printOff)

		// Evidence of up to four bytes stays on the line. The length once
		// included the color sequences, so colored evidence always qualifies.
		if lineLength(b, start, end, ev.on, e, ev.off)+1 > r.width && (len(e) > 4 || ev.on != "") {
			// Two-line output for long evidence strings
			b.WriteByte('\n')
			lineStart := b.Len()
			b.WriteString(briefLinePrefix)
			ev.wrap(b, e)
			truncateLine(b, lineStart, r.width)
		} else {
			// Single-line output for short evidence
			b.WriteByte(' ')
			ev.wrap(b, e)
		}
		b.WriteByte('\n')
	}

	return r.out.write(b.Bytes())
}

func (r *TerminalBrief) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// guard against nil reports
	// Non-diff files are handled on the fly by File()
	if rep == nil || rep.Diff == nil {
		return nil
	}

	return fmt.Errorf("diffs are unsupported by the TerminalBrief renderer")
}
