package refresh

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/chainguard-dev/malcontent/pkg/action"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

type actionData struct {
	format     string
	outputPath string
	scanPath   string
}

// actionSampleData contains paths and formats for test data in pkg/action.
var actionTestData = []actionData{
	{
		format:     "json",
		scanPath:   "pkg/action/testdata/static.tar.xz",
		outputPath: "pkg/action/testdata/scan_oci",
	},
	{
		format:     "json",
		scanPath:   "pkg/action/testdata/apko_nested.tar.gz",
		outputPath: "pkg/action/testdata/scan_archive",
	},
	{
		format:     "json",
		scanPath:   "pkg/action/testdata/conflict.zip",
		outputPath: "pkg/action/testdata/scan_conflict",
	},
}

func actionRefresh(ctx context.Context) ([]TestData, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	testData := make([]TestData, 0, len(actionTestData))

	for _, td := range actionTestData {
		output := td.outputPath
		scan := td.scanPath

		if _, err := os.Stat(scan); err != nil {
			return nil, fmt.Errorf("special case input file not found: %s: %w", scan, err)
		}

		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return nil, fmt.Errorf("create output directory: %w", err)
		}

		outFile, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create output file %s: %w", output, err)
		}

		r, err := render.New(td.format, outFile)
		if err != nil {
			return nil, fmt.Errorf("create renderer for %s: %w", output, err)
		}

		rfs := []fs.FS{rules.FS, thirdparty.FS}
		yrs, err := action.CachedRules(ctx, rfs)
		if err != nil {
			return nil, err
		}

		c := &malcontent.Config{
			Concurrency:           runtime.NumCPU(),
			IgnoreSelf:            false,
			MinFileRisk:           0,
			MinRisk:               0,
			OCI:                   false,
			QuantityIncreasesRisk: true,
			Renderer:              r,
			Rules:                 yrs,
			ScanPaths:             []string{scan},
			TrimPrefixes:          []string{"pkg/action/"},
		}

		testData = append(testData, TestData{
			Config:     c,
			OutputPath: output,
		})
	}
	return testData, nil
}
