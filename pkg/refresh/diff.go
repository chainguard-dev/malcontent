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

type diffData struct {
	destPath     string
	format       string
	minFileRisk  int
	minRisk      int
	outputPath   string
	riskChange   bool
	riskIncrease bool
	srcPath      string
}

// diffTestData contains paths, formats, and extra configuration for diff sample data.
var diffTestData = []diffData{
	{
		destPath:   "macOS/2023.3CX/libffmpeg.dirty.dylib",
		format:     "markdown",
		outputPath: "macOS/2023.3CX/libffmpeg.dirty.mdiff",
		srcPath:    "macOS/2023.3CX/libffmpeg.dylib",
	},
	{
		destPath:   "macOS/2023.3CX/libffmpeg.dirty.dylib",
		format:     "markdown",
		outputPath: "macOS/2023.3CX/libffmpeg.change_increase.mdiff",
		riskChange: true,
		srcPath:    "macOS/2023.3CX/libffmpeg.dylib",
	},
	{
		destPath:   "macOS/2023.3CX/libffmpeg.dylib",
		format:     "markdown",
		outputPath: "macOS/2023.3CX/libffmpeg.change_decrease.mdiff",
		riskChange: true,
		srcPath:    "macOS/2023.3CX/libffmpeg.dirty.dylib",
	},
	{
		destPath:   "macOS/2023.3CX/libffmpeg.dylib",
		format:     "markdown",
		outputPath: "macOS/2023.3CX/libffmpeg.change_no_change.mdiff",
		riskChange: true,
		srcPath:    "macOS/2023.3CX/libffmpeg.dylib",
	},
	{
		destPath:   "macOS/clean/ls",
		format:     "markdown",
		outputPath: "macOS/2023.3CX/libffmpeg.change_unrelated.mdiff",
		riskChange: true,
		srcPath:    "macOS/2023.3CX/libffmpeg.dylib",
	},
	{
		destPath:     "macOS/2023.3CX/libffmpeg.dirty.dylib",
		format:       "markdown",
		outputPath:   "macOS/2023.3CX/libffmpeg.increase.mdiff",
		riskIncrease: true,
		srcPath:      "macOS/2023.3CX/libffmpeg.dylib",
	},
	{
		destPath:     "macOS/2023.3CX/libffmpeg.dylib",
		format:       "markdown",
		outputPath:   "macOS/2023.3CX/libffmpeg.no_change.mdiff",
		riskIncrease: true,
		srcPath:      "macOS/2023.3CX/libffmpeg.dylib",
	},
	{
		destPath:     "macOS/2023.3CX/libffmpeg.dylib",
		format:       "markdown",
		outputPath:   "macOS/2023.3CX/libffmpeg.decrease.mdiff",
		riskIncrease: true,
		srcPath:      "macOS/2023.3CX/libffmpeg.dirty.dylib",
	},
	{
		destPath:     "macOS/2023.3CX/libffmpeg.dylib",
		format:       "markdown",
		outputPath:   "macOS/2023.3CX/libffmpeg.increase_unrelated.mdiff",
		riskIncrease: true,
		srcPath:      "macOS/clean/ls",
	},
	{
		destPath:   "linux/2023.FreeDownloadManager/freedownloadmanager_infected_postinst",
		format:     "simple",
		outputPath: "linux/2023.FreeDownloadManager/freedownloadmanager.sdiff",
		srcPath:    "linux/2023.FreeDownloadManager/freedownloadmanager_clear_postinst",
	},
	{
		destPath:   "linux/2024.sbcl.market/sbcl.dirty",
		format:     "simple",
		outputPath: "linux/2024.sbcl.market/sbcl.sdiff",
		srcPath:    "linux/2024.sbcl.market/sbcl.clean",
	},
	{
		destPath:   "linux/clean/aws-c-io/aws-c-io-0.14.11-r0.spdx.json",
		format:     "simple",
		outputPath: "linux/clean/aws-c-io/aws-c-io.sdiff",
		srcPath:    "linux/clean/aws-c-io/aws-c-io-0.14.10-r0.spdx.json",
	},
	{
		destPath:   "macOS/clean/ls",
		format:     "markdown",
		outputPath: "macOS/clean/ls.mdiff",
		srcPath:    "linux/clean/ls.x86_64",
	},
	{
		destPath:    "macOS/clean/ls",
		format:      "simple",
		minFileRisk: 2,
		minRisk:     2,
		outputPath:  "macOS/clean/ls.sdiff.level_2",
		srcPath:     "linux/clean/ls.x86_64",
	},
	{
		destPath:    "macOS/clean/ls",
		format:      "simple",
		minFileRisk: 2,
		minRisk:     1,
		outputPath:  "macOS/clean/ls.sdiff.trigger_2",
		srcPath:     "linux/clean/ls.x86_64",
	},
	{
		destPath:    "macOS/clean/ls",
		format:      "simple",
		minFileRisk: 3,
		minRisk:     1,
		outputPath:  "macOS/clean/ls.sdiff.trigger_3",
		srcPath:     "linux/clean/ls.x86_64",
	},
	{
		destPath:     "javascript/2024.lottie-player/lottie-player.min.js",
		format:       "markdown",
		outputPath:   "javascript/2024.lottie-player/lottie-player.min.js.mdiff",
		riskIncrease: true,
		srcPath:      "javascript/clean/lottie-player.min.js",
	},
}

func diffRefresh(ctx context.Context, rc Config) ([]TestData, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	testData := make([]TestData, 0, len(diffTestData))

	for _, td := range diffTestData {
		output := filepath.Join(rc.TestDataPath, td.outputPath)
		src := filepath.Join(rc.SamplesPath, td.srcPath)
		dest := filepath.Join(rc.SamplesPath, td.destPath)

		if _, err := os.Stat(src); err != nil {
			return nil, fmt.Errorf("risk case base file not found: %s: %w", src, err)
		}
		if _, err := os.Stat(dest); err != nil {
			return nil, fmt.Errorf("risk case compare file not found: %s: %w", dest, err)
		}

		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return nil, fmt.Errorf("create output directory: %w", err)
		}

		outFile, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create output file %s: %w", output, err)
		}

		renderer, err := render.New(td.format, outFile)
		if err != nil {
			return nil, fmt.Errorf("create renderer for %s: %w", output, err)
		}

		minFileRisk := 1
		minRisk := 1

		if td.minFileRisk != 0 {
			minFileRisk = td.minFileRisk
		}
		if td.minRisk != 0 {
			minRisk = td.minRisk
		}

		rfs := []fs.FS{rules.FS, thirdparty.FS}
		yrs, err := action.CachedRules(ctx, rfs)
		if err != nil {
			return nil, err
		}

		c := &malcontent.Config{
			Concurrency:           runtime.NumCPU(),
			FileRiskChange:        td.riskChange,
			FileRiskIncrease:      td.riskIncrease,
			MinFileRisk:           minFileRisk,
			MinRisk:               minRisk,
			QuantityIncreasesRisk: true,
			Renderer:              renderer,
			Rules:                 yrs,
			ScanPaths:             []string{src, dest},
			TrimPrefixes:          []string{rc.SamplesPath},
		}

		testData = append(testData, TestData{
			Config:     c,
			OutputPath: output,
		})
	}

	return testData, nil
}
