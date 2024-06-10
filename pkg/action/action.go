// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"io"

	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/hillu/go-yara/v4"
)

type Config struct {
	IgnoreSelf       bool
	IgnoreTags       []string
	IncludeDataFiles bool
	MinFileRisk      int
	MinRisk          int
	OCI              bool
	OmitEmpty        bool
	Output           io.Writer
	Renderer         render.Renderer
	Rules            *yara.Rules
	ScanPaths        []string
	Stats            bool
	ErrFirstMiss     bool
	ErrFirstHit      bool
}
