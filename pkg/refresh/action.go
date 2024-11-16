package refresh

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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
}

func actionRefresh() ([]TestData, error) {
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

		c := &malcontent.Config{
			IgnoreSelf:            false,
			MinFileRisk:           0,
			MinRisk:               0,
			OCI:                   false,
			QuantityIncreasesRisk: true,
			Renderer:              r,
			RuleFS:                []fs.FS{rules.FS, thirdparty.FS},
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
