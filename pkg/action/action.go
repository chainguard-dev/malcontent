// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"io"

	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/hillu/go-yara/v4"
)

type Config struct {
	Rules            *yara.Rules
	ScanPaths        []string
	IgnoreTags       []string
	MinResultScore   int
	MinFileScore     int
	OmitEmpty        bool
	IncludeDataFiles bool
	Renderer         render.Renderer
	Output           io.Writer
	OCI              bool
}
