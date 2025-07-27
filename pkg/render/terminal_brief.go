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
	"github.com/fatih/color"
)

type TerminalBrief struct {
	w io.Writer
}

func NewTerminalBrief(w io.Writer) TerminalBrief {
	return TerminalBrief{w: w}
}

func (r TerminalBrief) Name() string { return "TerminalBrief" }

func (r TerminalBrief) Scanning(_ context.Context, path string) {
	fmt.Fprintf(r.w, "🔎 Scanning %q\n", path)
}

func (r TerminalBrief) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr.Skipped != "" || len(fr.Behaviors) == 0 {
		return nil
	}

	width := suggestedWidth()
	fmt.Fprintf(r.w, "├─ %s %s\n", riskEmoji(fr.RiskScore), fr.Path)

	for _, b := range fr.Behaviors {
		content := fmt.Sprintf("│     %s %s — %s", riskColor(fr.RiskLevel, "•"), riskColor(fr.RiskLevel, b.ID), b.Description)
		fmt.Fprint(r.w, content)

		e := evidenceString(b.MatchStrings, b.Description)

		// no evidence to give
		if e == "" {
			fmt.Println(r.w, "")
			continue
		}

		color.New(color.FgHiBlack).Fprint(r.w, ":")
		e = color.RGB(255, 255, 255).Sprint(e)

		// Two-line output for long evidence strings
		if ansiLineLength(content+e)+1 > width && len(e) > 4 {
			fmt.Fprintln(r.w, "\n"+truncate(fmt.Sprintf("│     %s", e), width))
			continue
		}
		// Single-line output for short evidence
		fmt.Fprintln(r.w, " "+e)
	}

	return nil
}

func (r TerminalBrief) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
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
