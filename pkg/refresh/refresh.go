package refresh

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/action"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"golang.org/x/sync/errgroup"
)

// Config holds the configuration for refreshing sample test data.
type Config struct {
	Concurrency  int
	SamplesPath  string
	TestDataPath string
}

// TestData stores per-scan configuration and output location.
type TestData struct {
	Config     *malcontent.Config
	OutputPath string
}

// discoverTestData walks the test data directory and finds test files that follow
// consistent sample -> output naming.
func discoverTestData(rc Config) (map[string]string, error) {
	testFiles := make(map[string]string)

	err := filepath.Walk(rc.TestDataPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || strings.Contains(path, "pkg/action/testdata") {
			return nil
		}

		ext := filepath.Ext(path)
		switch ext {
		case ".simple", ".md", ".json":
			relPath, err := filepath.Rel(rc.TestDataPath, path)
			if err != nil {
				return fmt.Errorf("get relative path: %w", err)
			}

			samplePath := strings.TrimSuffix(relPath, ext)
			fullSamplePath := filepath.Join(rc.SamplesPath, samplePath)

			if _, err := os.Stat(fullSamplePath); err == nil {
				testFiles[path] = fullSamplePath
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk test data directory: %w", err)
	}

	return testFiles, nil
}

// newConfig returns a new malcontent Config with parent configurations.
func newConfig(rc Config) *malcontent.Config {
	return &malcontent.Config{
		Concurrency:           runtime.NumCPU(),
		IgnoreTags:            []string{"harmless"},
		MinFileRisk:           1,
		MinRisk:               1,
		QuantityIncreasesRisk: true,
		RuleFS:                []fs.FS{rules.FS, thirdparty.FS},
		TrimPrefixes:          []string{rc.SamplesPath},
	}
}

func prepareRefresh(ctx context.Context, rc Config) ([]TestData, error) {
	var testData []TestData

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	actions, err := actionRefresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieve action tasks: %w", err)
	}

	diffs, err := diffRefresh(ctx, rc)
	if err != nil {
		return nil, fmt.Errorf("retrieve risk tasks: %w", err)
	}

	testData = append(testData, actions...)
	testData = append(testData, diffs...)

	discovered, err := discoverTestData(rc)
	if err != nil {
		return nil, fmt.Errorf("find test files: %w", err)
	}

	for data, sample := range discovered {
		outFile, err := os.OpenFile(data, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create output file %s: %w", data, err)
		}

		ext := filepath.Ext(data)
		format := strings.TrimPrefix(ext, ".")
		switch format {
		case "sdiff":
			format = "simple"
		case "mdiff", "md":
			format = "markdown"
		}

		r, err := render.New(format, outFile)
		if err != nil {
			return nil, fmt.Errorf("create renderer for %s: %w", sample, err)
		}

		c := newConfig(rc)

		rfs := []fs.FS{rules.FS, thirdparty.FS}
		yrs, err := action.CachedRules(ctx, rfs)
		if err != nil {
			return nil, err
		}

		c.Renderer = r
		c.Rules = yrs

		if strings.HasSuffix(data, ".mdiff") || strings.HasSuffix(data, ".sdiff") {
			dirPath := filepath.Dir(sample)
			files, err := os.ReadDir(dirPath)
			if err != nil {
				return nil, fmt.Errorf("read directory %s: %w", dirPath, err)
			}

			var diffFiles []string
			baseName := filepath.Base(sample)
			for _, f := range files {
				if strings.Contains(f.Name(), strings.TrimSuffix(baseName, filepath.Ext(baseName))) {
					diffFiles = append(diffFiles, filepath.Join(dirPath, f.Name()))
				}
			}

			if len(diffFiles) == 2 {
				c.ScanPaths = diffFiles
				testData = append(testData, TestData{
					Config:     c,
					OutputPath: data,
				})
			}
		} else {
			c.ScanPaths = []string{sample}
			testData = append(testData, TestData{
				Config:     c,
				OutputPath: data,
			})
		}
	}

	return testData, nil
}

// executeRefresh reads from a populated slice of TestData.
func executeRefresh(ctx context.Context, c Config, testData []TestData, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	g, refreshCtx := errgroup.WithContext(ctx)

	var mu sync.Mutex
	completed := 0
	total := len(testData)

	g.SetLimit(c.Concurrency)
	for _, data := range testData {
		g.Go(func() error {
			select {
			case <-refreshCtx.Done():
				return refreshCtx.Err()
			default:
				var err error
				var res *malcontent.Report

				if len(data.Config.ScanPaths) == 2 {
					res, err = action.Diff(refreshCtx, *data.Config, logger)
				} else {
					res, err = action.Scan(refreshCtx, *data.Config)
				}

				if err != nil {
					return fmt.Errorf("refresh sample data for %s: %w", data.OutputPath, err)
				}

				if err := data.Config.Renderer.Full(ctx, nil, res); err != nil {
					return fmt.Errorf("render results for %s: %w", data.OutputPath, err)
				}

				mu.Lock()
				defer mu.Unlock()
				completed++
				fmt.Printf("\rSample data refreshed: %d/%d (progress/total)", completed, total)

				return nil
			}
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("test data refresh failed: %w", err)
	}

	fmt.Printf("\nSuccessfully refreshed test data for %d samples\n", total)
	return nil
}

// Refresh updates all relevant test data in pkg/action and tests.
func Refresh(ctx context.Context, rc Config, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check if UPX is present which is required for certain refreshes
	if err := programkind.UPXInstalled(); err != nil {
		return fmt.Errorf("required UPX installation not found: %w", err)
	}
	if rc.SamplesPath == "" {
		return fmt.Errorf("sample location is required")
	}
	if rc.TestDataPath == "" {
		return fmt.Errorf("test data location required")
	}
	if rc.Concurrency < 1 {
		rc.Concurrency = 1
	}

	// Ensure samples directory exists
	// When running make refresh-sample-testdata this will be handled automatically
	if info, err := os.Stat(rc.SamplesPath); err != nil {
		return fmt.Errorf("sample directory not found: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("sample path is not a directory")
	}

	testData, err := prepareRefresh(ctx, rc)
	if err != nil {
		return fmt.Errorf("failed to prepare sample data refresh: %w", err)
	}

	return executeRefresh(ctx, rc, testData, logger)
}
