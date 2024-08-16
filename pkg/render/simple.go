// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
)

type Simple struct {
	w io.Writer
}

func NewSimple(w io.Writer) Simple {
	return Simple{w: w}
}

func (r Simple) File(_ context.Context, fr *bincapz.FileReport) error {
	if fr.Skipped != "" {
		return nil
	}

	if len(fr.Behaviors) > 0 {
		fmt.Fprintf(r.w, "# %s\n", fr.Path)
	}

	var bs []*bincapz.Behavior

	bs = append(bs, fr.Behaviors...)

	sort.Slice(bs, func(i, j int) bool {
		return bs[i].ID < bs[j].ID
	})

	for _, b := range bs {
		fmt.Fprintf(r.w, "%s\n", b.ID)
	}
	return nil
}

func (r Simple) Full(_ context.Context, rep *bincapz.Report) error {
	if rep.Diff == nil {
		return nil
	}

	for removed := rep.Diff.Removed.Oldest(); removed != nil; removed = removed.Next() {
		fmt.Fprintf(r.w, "--- missing: %s\n", removed.Key)

		var bs []*bincapz.Behavior
		bs = append(bs, removed.Value.Behaviors...)

		sort.Slice(bs, func(i, j int) bool {
			return bs[i].ID < bs[j].ID
		})

		for _, b := range bs {
			fmt.Fprintf(r.w, "-%s\n", b.ID)
		}
	}

	for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
		fmt.Fprintf(r.w, "++++ added: %s\n", added.Key)

		var bs []*bincapz.Behavior
		bs = append(bs, added.Value.Behaviors...)

		sort.Slice(bs, func(i, j int) bool {
			return bs[i].ID < bs[j].ID
		})

		for _, b := range bs {
			fmt.Fprintf(r.w, "+%s\n", b.ID)
		}
	}

	for modified := rep.Diff.Modified.Oldest(); modified != nil; modified = modified.Next() {
		if modified.Value.PreviousRelPath != "" && modified.Value.PreviousRelPathScore >= 0.9 {
			fmt.Fprintf(r.w, ">>> moved: %s -> %s (score: %f)\n", modified.Value.PreviousRelPath, modified.Value.Path, modified.Value.PreviousRelPathScore)
		} else {
			fmt.Fprintf(r.w, "*** changed: %s\n", modified.Value.Path)
		}

		var bs []*bincapz.Behavior
		bs = append(bs, modified.Value.Behaviors...)

		sort.Slice(bs, func(i, j int) bool {
			return bs[i].ID < bs[j].ID
		})

		for i := range bs {
			b := bs[i]
			if b.DiffRemoved {
				fmt.Fprintf(r.w, "-%s\n", b.ID)
				continue
			}
			if b.DiffAdded {
				fmt.Fprintf(r.w, "+%s\n", b.ID)
			}
		}
	}

	return nil
}
