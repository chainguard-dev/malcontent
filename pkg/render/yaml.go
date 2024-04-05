// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
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

func (r YAML) File(_ context.Context, _ bincapz.FileReport) error {
	return nil
}

func (r YAML) Full(_ context.Context, rep bincapz.Report) error {
	yaml, err := yaml.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.w, "%s\n", yaml)
	return err
}
