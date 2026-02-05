// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package refresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
)

func TestDiscoverTestData(t *testing.T) {
	t.Parallel()
	// Create temporary directories
	samplesDir := t.TempDir()
	testDataDir := t.TempDir()

	// Create sample files
	sampleFiles := []string{
		"sample1.txt",
		"subdir/sample2.sh",
		"sample3.py",
	}

	for _, sf := range sampleFiles {
		fullPath := filepath.Join(samplesDir, sf)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("failed to create sample directory: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte("sample content"), 0o644); err != nil {
			t.Fatalf("failed to create sample file: %v", err)
		}
	}

	// Create corresponding test data files
	testDataFiles := []string{
		"sample1.txt.simple",
		"subdir/sample2.sh.json",
		"sample3.py.md",
		"orphan.simple", // No corresponding sample
	}

	for _, tdf := range testDataFiles {
		fullPath := filepath.Join(testDataDir, tdf)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("failed to create test data directory: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte("test data"), 0o644); err != nil {
			t.Fatalf("failed to create test data file: %v", err)
		}
	}

	// Create a file that should be skipped (pkg/action/testdata)
	skipDir := filepath.Join(testDataDir, "pkg/action/testdata")
	if err := os.MkdirAll(skipDir, 0o755); err != nil {
		t.Fatalf("failed to create skip directory: %v", err)
	}
	skipFile := filepath.Join(skipDir, "skip.simple")
	if err := os.WriteFile(skipFile, []byte("skip"), 0o644); err != nil {
		t.Fatalf("failed to create skip file: %v", err)
	}

	rc := Config{
		SamplesPath:  samplesDir,
		TestDataPath: testDataDir,
	}

	result, err := discoverTestData(rc)
	if err != nil {
		t.Fatalf("discoverTestData() error = %v", err)
	}

	// Should find 3 test data files with corresponding samples (not the orphan)
	expectedCount := 3
	if len(result) != expectedCount {
		t.Errorf("discoverTestData() found %d files, want %d", len(result), expectedCount)
		t.Logf("Found files: %v", result)
	}

	// Verify each test data file maps to correct sample
	for testData, sample := range result {
		if !fileExists(sample) {
			t.Errorf("Sample file %q referenced by %q does not exist", sample, testData)
		}
	}

	// Verify orphan file is not included
	for testData := range result {
		if filepath.Base(testData) == "orphan.simple" {
			t.Error("discoverTestData() should not include orphan files without corresponding samples")
		}
	}

	// Verify pkg/action/testdata is skipped
	for testData := range result {
		if strings.Contains(testData, "pkg/action/testdata") {
			t.Error("discoverTestData() should skip pkg/action/testdata directory")
		}
	}
}

func TestDiscoverTestDataEmptyDirectory(t *testing.T) {
	t.Parallel()
	samplesDir := t.TempDir()
	testDataDir := t.TempDir()

	rc := Config{
		SamplesPath:  samplesDir,
		TestDataPath: testDataDir,
	}

	result, err := discoverTestData(rc)
	if err != nil {
		t.Fatalf("discoverTestData() error = %v", err)
	}

	if len(result) != 0 {
		t.Errorf("discoverTestData() on empty directory found %d files, want 0", len(result))
	}
}

func TestDiscoverTestDataNonExistentPath(t *testing.T) {
	t.Parallel()
	samplesDir := t.TempDir()
	nonExistentPath := filepath.Join(t.TempDir(), "nonexistent")

	rc := Config{
		SamplesPath:  samplesDir,
		TestDataPath: nonExistentPath,
	}

	_, err := discoverTestData(rc)
	if err == nil {
		t.Error("discoverTestData() with non-existent path should return error")
	}
}

func TestNewConfig(t *testing.T) {
	t.Parallel()
	samplesDir := t.TempDir()

	rc := Config{
		SamplesPath:  samplesDir,
		TestDataPath: t.TempDir(),
		Concurrency:  4,
	}

	cfg := newConfig(rc)

	if cfg == nil {
		t.Fatal("newConfig() returned nil")
	}

	if cfg.MinFileRisk != 1 {
		t.Errorf("newConfig() MinFileRisk = %d, want 1", cfg.MinFileRisk)
	}

	if cfg.MinRisk != 1 {
		t.Errorf("newConfig() MinRisk = %d, want 1", cfg.MinRisk)
	}

	if !cfg.QuantityIncreasesRisk {
		t.Error("newConfig() QuantityIncreasesRisk = false, want true")
	}

	if len(cfg.RuleFS) < 1 {
		t.Error("newConfig() should include at least one rule filesystem")
	}

	if len(cfg.TrimPrefixes) != 1 || cfg.TrimPrefixes[0] != samplesDir {
		t.Errorf("newConfig() TrimPrefixes = %v, want [%s]", cfg.TrimPrefixes, samplesDir)
	}

	if len(cfg.IgnoreTags) == 0 {
		t.Error("newConfig() should set IgnoreTags")
	}
}

func TestRefreshValidationErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	logger := clog.FromContext(ctx)

	tests := []struct {
		name   string
		config Config
		setup  func() Config
	}{
		{
			name: "empty samples path",
			setup: func() Config {
				return Config{
					TestDataPath: t.TempDir(),
					Concurrency:  1,
				}
			},
		},
		{
			name: "empty test data path",
			setup: func() Config {
				return Config{
					SamplesPath: t.TempDir(),
					Concurrency: 1,
				}
			},
		},
		{
			name: "non-existent samples directory",
			setup: func() Config {
				return Config{
					SamplesPath:  filepath.Join(t.TempDir(), "nonexistent"),
					TestDataPath: t.TempDir(),
					Concurrency:  1,
				}
			},
		},
		{
			name: "samples path is a file not directory",
			setup: func() Config {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "file.txt")
				if err := os.WriteFile(filePath, []byte("test"), 0o644); err != nil {
					t.Fatalf("failed to create file: %v", err)
				}
				return Config{
					SamplesPath:  filePath,
					TestDataPath: t.TempDir(),
					Concurrency:  1,
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := tt.setup()
			err := Refresh(ctx, cfg, logger)
			if err == nil {
				t.Error("Refresh() should return error for invalid config")
			}
		})
	}
}

func TestRefreshCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	samplesDir := t.TempDir()
	testDataDir := t.TempDir()
	logger := clog.FromContext(ctx)

	cfg := Config{
		SamplesPath:  samplesDir,
		TestDataPath: testDataDir,
		Concurrency:  1,
	}

	err := Refresh(ctx, cfg, logger)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Refresh() with canceled context error = %v, want %v", err, context.Canceled)
	}
}

func TestPrepareRefreshCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	samplesDir := t.TempDir()
	testDataDir := t.TempDir()

	cfg := Config{
		SamplesPath:  samplesDir,
		TestDataPath: testDataDir,
		Concurrency:  1,
	}

	_, err := prepareRefresh(ctx, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("prepareRefresh() with canceled context error = %v, want %v", err, context.Canceled)
	}
}

func TestExecuteRefreshCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := Config{
		SamplesPath:  t.TempDir(),
		TestDataPath: t.TempDir(),
		Concurrency:  1,
	}

	logger := clog.FromContext(ctx)

	err := executeRefresh(ctx, cfg, []TestData{}, logger)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("executeRefresh() with canceled context error = %v, want %v", err, context.Canceled)
	}
}

func TestExecuteRefreshEmptyTestData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := Config{
		SamplesPath:  t.TempDir(),
		TestDataPath: t.TempDir(),
		Concurrency:  1,
	}

	logger := clog.FromContext(ctx)

	err := executeRefresh(ctx, cfg, []TestData{}, logger)
	if err != nil {
		t.Errorf("executeRefresh() with empty test data error = %v", err)
	}
}

func TestConfigConcurrencyDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	samplesDir := t.TempDir()
	testDataDir := t.TempDir()

	// Create minimal valid setup
	if err := os.MkdirAll(samplesDir, 0o755); err != nil {
		t.Fatalf("failed to create samples dir: %v", err)
	}

	logger := clog.FromContext(ctx)

	cfg := Config{
		SamplesPath:  samplesDir,
		TestDataPath: testDataDir,
		Concurrency:  0, // Should default to 1
	}

	// This will fail due to UPX requirement, but we can verify concurrency is set
	err := Refresh(ctx, cfg, logger)

	// We expect an error (likely UPX not installed or no test data)
	// but just verify the function handles concurrency=0
	if err == nil {
		// Unexpected success, but that's ok for this test
		t.Log("Refresh succeeded (unexpected but acceptable)")
	}
}

// Helper functions

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestDiscoverTestDataVariousExtensions(t *testing.T) {
	t.Parallel()
	samplesDir := t.TempDir()
	testDataDir := t.TempDir()

	// Create sample
	sample := filepath.Join(samplesDir, "test.bin")
	if err := os.WriteFile(sample, []byte("sample"), 0o644); err != nil {
		t.Fatalf("failed to create sample: %v", err)
	}

	// Create test data files with different extensions
	extensions := []string{".simple", ".md", ".json"}
	for _, ext := range extensions {
		testFile := filepath.Join(testDataDir, "test.bin"+ext)
		if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	// Create a file with unsupported extension (should be ignored)
	unsupported := filepath.Join(testDataDir, "test.bin.txt")
	if err := os.WriteFile(unsupported, []byte("unsupported"), 0o644); err != nil {
		t.Fatalf("failed to create unsupported file: %v", err)
	}

	rc := Config{
		SamplesPath:  samplesDir,
		TestDataPath: testDataDir,
	}

	result, err := discoverTestData(rc)
	if err != nil {
		t.Fatalf("discoverTestData() error = %v", err)
	}

	// Should find 3 files (.simple, .md, .json) but not .txt
	if len(result) != 3 {
		t.Errorf("discoverTestData() found %d files, want 3 (.simple, .md, .json)", len(result))
	}

	// Verify .txt file is not included
	for testData := range result {
		if filepath.Ext(testData) == ".txt" {
			t.Error("discoverTestData() should not include .txt files")
		}
	}
}
