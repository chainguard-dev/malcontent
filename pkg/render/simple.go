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
	if fr.Path != "" {
		fmt.Fprintf(r.w, "# %s\n", fr.Path)
	}
	bs := []string{}

	for k := range fr.Behaviors {
		bs = append(bs, k)
	}
	sort.Strings(bs)
	for _, k := range bs {
		fmt.Fprintf(r.w, "%s\n", k)
	}
	return nil
}

func (r Simple) Full(_ context.Context, rep *bincapz.Report) error {
	if rep.Diff == nil {
		return nil
	}

	for f, fr := range rep.Diff.Removed {
		fmt.Fprintf(r.w, "--- missing: %s\n", f)

		bs := []string{}
		for k := range fr.Behaviors {
			bs = append(bs, k)
		}
		sort.Strings(bs)

		for _, k := range bs {
			fmt.Fprintf(r.w, "-%s\n", k)
		}
	}

	for f, fr := range rep.Diff.Removed {
		fmt.Fprintf(r.w, "++++ added: %s\n", f)
		bs := []string{}
		for k := range fr.Behaviors {
			bs = append(bs, k)
		}
		sort.Strings(bs)

		for _, k := range bs {
			fmt.Fprintf(r.w, "+%s\n", k)
		}
	}

	for f, fr := range rep.Diff.Modified {
		if fr.PreviousRelPath != "" {
			fmt.Fprintf(r.w, ">>> moved: %s -> %s (score: %f)\n", fr.PreviousRelPath, f, fr.PreviousRelPathScore)
		} else {
			fmt.Fprintf(r.w, "*** changed: %s\n", fr.Path)
		}
		bs := []string{}
		for k := range fr.Behaviors {
			bs = append(bs, k)
		}
		sort.Strings(bs)

		for _, k := range bs {
			b := fr.Behaviors[k]
			if b.DiffRemoved {
				fmt.Fprintf(r.w, "-%s\n", k)
				continue
			}
			if b.DiffAdded {
				fmt.Fprintf(r.w, "+%s\n", k)
			}
		}
	}
	return nil
}
