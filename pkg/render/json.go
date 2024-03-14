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

func (r JSON) File(fr bincapz.FileReport) error {
	return nil
}

func (r JSON) Full(rep bincapz.Report) error {
	json, err := json.MarshalIndent(rep, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", json)
	return err
}
