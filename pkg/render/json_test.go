// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

func TestJSONRendererEmpty(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: sync.Map{},
	}

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error = %v", err)
	}

	// Verify valid JSON was generated
	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid JSON: %v", err)
	}
}

func TestJSONRendererWithFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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

	// Parse and verify JSON
	var result Report
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid JSON: %v", err)
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
		t.Error("File /bin/ls not found in JSON output")
	}
}

func TestJSONRendererWithSkippedFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid JSON: %v", err)
	}

	// Skipped files should be filtered out
	if len(result.Files) != 1 {
		t.Errorf("Expected 1 file (skipped should be filtered), got %d", len(result.Files))
	}

	if _, ok := result.Files["/bin/skipped"]; ok {
		t.Error("Skipped file should not appear in JSON output")
	}
}

func TestJSONRendererNilReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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

func TestJSONRendererCanceledContext(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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

func TestJSONRendererWithStats(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid JSON: %v", err)
	}

	// Stats should be present when enabled
	if result.Stats == nil {
		t.Error("Expected stats in output when Stats=true")
	}
}

func TestJSONRendererWithDiff(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Generated invalid JSON: %v", err)
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

func TestJSONRendererScanningNoOp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	// Scanning should be a no-op for JSON renderer
	renderer.Scanning(context.Background(), "/some/path")

	if buf.Len() != 0 {
		t.Error("Scanning() should not write anything for JSON renderer")
	}
}

func TestJSONRendererFileNoOp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	fr := &malcontent.FileReport{Path: "/test"}
	err := renderer.File(context.Background(), fr)
	if err != nil {
		t.Errorf("File() error = %v", err)
	}

	if buf.Len() != 0 {
		t.Error("File() should not write anything for JSON renderer")
	}
}

func TestJSONRendererSpecialCharacters(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	ctx := context.Background()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: sync.Map{},
	}

	// Add file with special characters
	report.Files.Store("/bin/test\"quote'", &malcontent.FileReport{
		Path:      "/bin/test\"quote'",
		RiskScore: 1,
	})

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error = %v", err)
	}

	// Should produce valid JSON despite special characters
	var result Report
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON with special characters: %v", err)
	}
}
