// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

type Simple struct {
	w io.Writer
}

func NewSimple(w io.Writer) Simple {
	return Simple{w: w}
}

func (r Simple) Name() string { return "Simple" }

func (r Simple) Scanning(_ context.Context, _ string) {}

func (r Simple) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr.Skipped != "" {
		return nil
	}

	if len(fr.Behaviors) > 0 {
		fmt.Fprintf(r.w, "# %s: %s\n", fr.Path, strings.ToLower(fr.RiskLevel))
	}

	for _, b := range fr.Behaviors {
		fmt.Fprintf(r.w, "%s: %s\n", b.ID, strings.ToLower(b.RiskLevel))
	}
	return nil
}

func (r Simple) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// guard against nil reports
	if rep == nil || rep.Diff == nil {
		return nil
	}

	for removed := rep.Diff.Removed.Oldest(); removed != nil; removed = removed.Next() {
		if len(removed.Value.Behaviors) == 0 {
			continue
		}

		fmt.Fprintf(r.w, "--- missing: %s\n", removed.Key)

		for _, b := range removed.Value.Behaviors {
			fmt.Fprintf(r.w, "-%s\n", b.ID)
		}
	}

	for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
		if len(added.Value.Behaviors) == 0 {
			continue
		}

		fmt.Fprintf(r.w, "+++ added: %s\n", added.Key)

		for _, b := range added.Value.Behaviors {
			fmt.Fprintf(r.w, "+%s\n", b.ID)
		}
	}

	count := func(bs []*malcontent.Behavior) (int, int) {
		var added, removed int
		for _, b := range bs {
			if b.DiffAdded {
				added++
			}
			if b.DiffRemoved {
				removed++
			}
		}

		return added, removed
	}

	for modified := rep.Diff.Modified.Oldest(); modified != nil; modified = modified.Next() {
		if len(modified.Value.Behaviors) == 0 {
			continue
		}

		added, removed := count(modified.Value.Behaviors)
		if added == 0 && removed == 0 {
			continue
		}

		if modified.Value.PreviousPath != "" {
			fmt.Fprintf(r.w, ">>> moved (%d added, %d removed): %s -> %s\n", added, removed, modified.Value.PreviousPath, modified.Value.Path)
		} else {
			fmt.Fprintf(r.w, "*** changed (%d added, %d removed): %s\n", added, removed, modified.Value.Path)
		}

		for _, b := range modified.Value.Behaviors {
			if !b.DiffRemoved && !b.DiffAdded {
				continue
			}
			if b.DiffRemoved {
				fmt.Fprintf(r.w, "-%s\n", b.ID)
			}
			if b.DiffAdded {
				fmt.Fprintf(r.w, "+%s\n", b.ID)
			}
		}
	}

	return nil
}
