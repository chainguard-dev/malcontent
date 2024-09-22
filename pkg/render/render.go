// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// New returns a new Renderer.
func New(kind string, w io.Writer) (malcontent.Renderer, error) {
	switch kind {
	case "", "auto", "terminal":
		return NewTerminal(w), nil
	case "terminal_brief":
		return NewTerminalBrief(w), nil
	case "markdown":
		return NewMarkdown(w), nil
	case "yaml":
		return NewYAML(w), nil
	case "json":
		return NewJSON(w), nil
	case "simple":
		return NewSimple(w), nil
	default:
		return nil, fmt.Errorf("unknown renderer: %q", kind)
	}
}

func riskEmoji(score int) string {
	symbol := "✅"
	switch score {
	case 2:
		symbol = "⚠️"
	case 3:
		symbol = "🔥"
	case 4:
		symbol = "🚨"
	}

	return symbol
}
