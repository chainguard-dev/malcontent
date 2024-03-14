package render

import (
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

func (r Simple) File(fr bincapz.FileReport) error {
	fmt.Fprintf(r.w, "%s\n", fr.Path)
	bs := []string{}

	for k := range fr.Behaviors {
		bs = append(bs, k)
	}
	sort.Strings(bs)
	for _, k := range bs {
		fmt.Fprintf(r.w, "  * %s\n", k)
	}
	return nil
}

func (r Simple) Full(rep bincapz.Report) error {
	for f, fr := range rep.Diff.Removed {
		fmt.Fprintf(r.w, "--- missing: %s\n", f)
		for k := range fr.Behaviors {
			fmt.Fprintf(r.w, "-%s\n", k)
		}
	}

	for f, fr := range rep.Diff.Removed {
		fmt.Fprintf(r.w, "++++ added: %s\n", f)
		for k := range fr.Behaviors {
			fmt.Fprintf(r.w, "+%s\n", k)
		}
	}

	for _, fr := range rep.Diff.Modified {
		fmt.Fprintf(r.w, "*** changed: %s\n", fr.Path)
		for k, b := range fr.Behaviors {
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
