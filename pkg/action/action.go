// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"io"

	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/hillu/go-yara/v4"
)

type Config struct {
	ExcludePaths     []string
	IncludePaths     []string
	IgnoreTags       []string
	IncludeDataFiles bool
	MinFileScore     int
	MinResultScore   int
	OCI              bool
	OmitEmpty        bool
	Output           io.Writer
	Renderer         render.Renderer
	Rules            *yara.Rules
	ScanPaths        []string
	Stats            bool
}
