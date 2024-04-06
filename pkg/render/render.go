// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
)

// Renderer is a common interface for Renderers.
type Renderer interface {
	File(context.Context, bincapz.FileReport) error
	Full(context.Context, bincapz.Report) error
}

// New returns a new Renderer.
func New(kind string, w io.Writer) (Renderer, error) {
	switch kind {
	case "", "auto", "terminal":
		return NewTerminal(w), nil
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
