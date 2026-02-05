// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"gopkg.in/yaml.v3"
)

func TestYAMLRendererEmpty(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: sync.Map{},
	}

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error = %v", err)
	}

	// Verify valid YAML was generated
	var result map[string]any
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid YAML: %v", err)
	}
}

func TestYAMLRendererWithFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: sync.Map{},
	}

	// Add a file report
	report.Files.Store("/bin/ls", &malcontent.FileReport{
		Path:      "/bin/ls",
		RiskScore: 1,
		RiskLevel: "low",
	})

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error = %v", err)
	}

	// Parse and verify YAML
	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid YAML: %v", err)
	}

	if len(result.Files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(result.Files))
	}

	if fr, ok := result.Files["/bin/ls"]; ok {
		if fr.Path != "/bin/ls" {
			t.Errorf("File path = %q, want %q", fr.Path, "/bin/ls")
		}
		if fr.RiskScore != 1 {
			t.Errorf("Risk score = %d, want 1", fr.RiskScore)
		}
	} else {
		t.Error("File /bin/ls not found in YAML output")
	}
}

func TestYAMLRendererWithSkippedFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: sync.Map{},
	}

	// Add a skipped file (should be filtered out)
	report.Files.Store("/bin/skipped", &malcontent.FileReport{
		Path:    "/bin/skipped",
		Skipped: "reason",
	})

	// Add a normal file
	report.Files.Store("/bin/normal", &malcontent.FileReport{
		Path:      "/bin/normal",
		RiskScore: 2,
	})

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error = %v", err)
	}

	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid YAML: %v", err)
	}

	// Skipped files should be filtered out
	if len(result.Files) != 1 {
		t.Errorf("Expected 1 file (skipped should be filtered), got %d", len(result.Files))
	}

	if _, ok := result.Files["/bin/skipped"]; ok {
		t.Error("Skipped file should not appear in YAML output")
	}
}

func TestYAMLRendererNilReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{}

	err := renderer.Full(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("Full() with nil report error = %v", err)
	}

	// Buffer should be empty for nil report
	if buf.Len() != 0 {
		t.Errorf("Expected empty output for nil report, got %d bytes", buf.Len())
	}
}

func TestYAMLRendererCanceledContext(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: sync.Map{},
	}

	err := renderer.Full(ctx, cfg, report)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Full() with canceled context error = %v, want %v", err, context.Canceled)
	}
}

func TestYAMLRendererWithStats(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{Stats: true}
	report := &malcontent.Report{
		Files: sync.Map{},
	}

	// Add some files to generate stats
	report.Files.Store("/bin/test1", &malcontent.FileReport{
		Path:      "/bin/test1",
		RiskScore: 2,
	})

	report.Files.Store("/bin/test2", &malcontent.FileReport{
		Path:      "/bin/test2",
		RiskScore: 3,
	})

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error = %v", err)
	}

	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid YAML: %v", err)
	}

	// Stats should be present when enabled
	if result.Stats == nil {
		t.Error("Expected stats in output when Stats=true")
	}
}

func TestYAMLRendererWithDiff(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{Stats: true}
	diff := &malcontent.DiffReport{
		Added:    orderedmap.New[string, *malcontent.FileReport](),
		Removed:  orderedmap.New[string, *malcontent.FileReport](),
		Modified: orderedmap.New[string, *malcontent.FileReport](),
	}
	diff.Added.Set("/bin/added", &malcontent.FileReport{Path: "/bin/added", RiskScore: 2})
	diff.Removed.Set("/bin/removed", &malcontent.FileReport{Path: "/bin/removed", RiskScore: 1})
	diff.Modified.Set("/bin/modified", &malcontent.FileReport{Path: "/bin/modified", RiskScore: 3})
	report := &malcontent.Report{
		Files: sync.Map{},
		Diff:  diff,
	}

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error = %v", err)
	}

	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid YAML: %v", err)
	}

	// Diff should be present
	if result.Diff == nil {
		t.Error("Expected diff in output")
	}

	// Stats should not be present for diff reports
	if result.Stats != nil {
		t.Error("Stats should not be present in diff reports")
	}
}

func TestYAMLRendererScanningNoOp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	// Scanning should be a no-op for YAML renderer
	renderer.Scanning(context.Background(), "/some/path")

	if buf.Len() != 0 {
		t.Error("Scanning() should not write anything for YAML renderer")
	}
}

func TestYAMLRendererFileNoOp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	fr := &malcontent.FileReport{Path: "/test"}
	err := renderer.File(context.Background(), fr)
	if err != nil {
		t.Errorf("File() error = %v", err)
	}

	if buf.Len() != 0 {
		t.Error("File() should not write anything for YAML renderer")
	}
}

func TestYAMLRendererSpecialCharacters(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: sync.Map{},
	}

	// Add file with special characters
	report.Files.Store("/bin/test:colon", &malcontent.FileReport{
		Path:      "/bin/test:colon",
		RiskScore: 1,
	})

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error = %v", err)
	}

	// Should produce valid YAML despite special characters
	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse YAML with special characters: %v", err)
	}
}

func TestYAMLRendererMultipleFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: sync.Map{},
	}

	// Add multiple files
	for i := 1; i <= 5; i++ {
		path := "/bin/test" + string(rune('0'+i))
		report.Files.Store(path, &malcontent.FileReport{
			Path:      path,
			RiskScore: i % 5,
		})
	}

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error = %v", err)
	}

	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid YAML: %v", err)
	}

	if len(result.Files) != 5 {
		t.Errorf("Expected 5 files, got %d", len(result.Files))
	}
}
