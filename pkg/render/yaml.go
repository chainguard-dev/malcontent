package render

import (
	"fmt"
	"io"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"gopkg.in/yaml.v3"
)

type YAML struct {
	w io.Writer
}

func NewYAML(w io.Writer) YAML {
	return YAML{w: w}
}

func (r YAML) File(_ bincapz.FileReport) error {
	return nil
}

func (r YAML) Full(rep bincapz.Report) error {
	yaml, err := yaml.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", yaml)
	return err
}
