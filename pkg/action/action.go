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
	MinLevel         int
	OmitEmpty        bool
	IncludeDataFiles bool
	Renderer         render.Renderer
	Output           io.Writer
}
