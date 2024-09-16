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
	"strings"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/fatih/color"
)

type TerminalBrief struct {
	w io.Writer
}

func NewTerminalBrief(w io.Writer) TerminalBrief {
	return TerminalBrief{w: w}
}

func briefRiskColor(level string) string {
	switch level {
	case "LOW":
		return color.HiGreenString("LOW ")
	case "MEDIUM", "MED":
		return color.HiYellowString("MED ")
	case "HIGH":
		return color.HiRedString("HIGH")
	case "CRITICAL", "CRIT":
		return color.HiMagentaString("CRIT")
	default:
		return color.WhiteString(level)
	}
}

func (r TerminalBrief) File(_ context.Context, fr *bincapz.FileReport) error {
	if len(fr.Behaviors) == 0 {
		return nil
	}

	reasons := []string{}
	for _, b := range fr.Behaviors {
		reasons = append(reasons, fmt.Sprintf("%s %s%s%s", color.HiYellowString(b.ID), color.HiBlackString("("), b.Description, color.HiBlackString(")")))
	}

	fmt.Fprintf(r.w, "%s%s%s %s: %s", color.HiBlackString("["), briefRiskColor(fr.RiskLevel), color.HiBlackString("]"), color.HiGreenString(fr.Path),
		strings.Join(reasons, color.HiBlackString(", ")))
	return nil
}

func (r TerminalBrief) Full(_ context.Context, rep *bincapz.Report) error {
	// Non-diff files are handled on the fly by File()
	if rep.Diff == nil {
		return nil
	}

	return fmt.Errorf("diffs are unsupported by the TerminalBrief renderer")
}
