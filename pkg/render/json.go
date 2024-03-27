package render

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
)

type JSON struct {
	w io.Writer
}

func NewJSON(w io.Writer) JSON {
	return JSON{w: w}
}

func (r JSON) File(_ bincapz.FileReport) error {
	return nil
}

func (r JSON) Full(rep bincapz.Report) error {
	j, err := json.MarshalIndent(rep, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", j)
	return err
}
