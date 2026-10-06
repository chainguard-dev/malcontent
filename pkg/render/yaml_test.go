// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"gopkg.in/yaml.v3"
)

func TestYAMLRendererEmpty(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
	}

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	// Verify valid YAML was generated
	var result map[string]any
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}
}

func TestYAMLRendererWithFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
	}

	// Add a file report
	report.Files.Store("/bin/ls", &malcontent.FileReport{
		Path:      "/bin/ls",
		RiskScore: 1,
		RiskLevel: "low",
	})

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	// Parse and verify YAML
	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}

	if len(result.Files) != 1 {
		t.Errorf("files: got = %d, want = 1", len(result.Files))
	}

	if fr, ok := result.Files["/bin/ls"]; ok {
		if fr.Path != "/bin/ls" {
			t.Errorf("file path: got = %q, want = %q", fr.Path, "/bin/ls")
		}
		if fr.RiskScore != 1 {
			t.Errorf("risk score: got = %d, want = 1", fr.RiskScore)
		}
	} else {
		t.Error("file /bin/ls: got = absent, want = present")
	}
}

func TestYAMLRendererWithSkippedFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
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
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}

	// Skipped files should be filtered out
	if len(result.Files) != 1 {
		t.Errorf("files excluding skipped: got = %d, want = 1", len(result.Files))
	}

	if _, ok := result.Files["/bin/skipped"]; ok {
		t.Error("skipped file: got = present, want = absent")
	}
}

func TestYAMLRendererNilReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{}

	err := renderer.Full(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("Full(nil report) error: got = %v, want = nil", err)
	}

	// Buffer should be empty for nil report
	if buf.Len() != 0 {
		t.Errorf("output for nil report: got = %d bytes, want = 0", buf.Len())
	}
}

func TestYAMLRendererCanceledContext(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
	}

	err := renderer.Full(ctx, cfg, report)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Full() with canceled context error: got = %v, want = %v", err, context.Canceled)
	}
}

func TestYAMLRendererWithStats(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{Stats: true}
	report := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
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
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}

	// Stats should be present when enabled
	if result.Stats == nil {
		t.Error("stats with Stats=true: got = absent, want = present")
	}
}

func TestYAMLRendererWithDiff(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := t.Context()
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
		Files: xsync.NewMap[string, *malcontent.FileReport](),
		Diff:  diff,
	}

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}

	// Diff should be present
	if result.Diff == nil {
		t.Error("diff: got = absent, want = present")
	}

	// Stats should not be present for diff reports
	if result.Stats != nil {
		t.Error("stats in diff report: got = present, want = absent")
	}
}

func TestYAMLRendererScanningNoOp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	// Scanning should be a no-op for YAML renderer
	renderer.Scanning(t.Context(), "/some/path")

	if buf.Len() != 0 {
		t.Errorf("Scanning() output: got = %q, want = empty", buf.String())
	}
}

func TestYAMLRendererDiffWithNilFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{}
	diff := &malcontent.DiffReport{
		Added:    orderedmap.New[string, *malcontent.FileReport](),
		Removed:  orderedmap.New[string, *malcontent.FileReport](),
		Modified: orderedmap.New[string, *malcontent.FileReport](),
	}
	diff.Added.Set("/bin/added", &malcontent.FileReport{Path: "/bin/added", RiskScore: 2})
	// Mirror what action.Diff() actually returns: Diff set, Files nil
	report := &malcontent.Report{Diff: diff}

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}

	if result.Diff == nil {
		t.Error("diff: got = absent, want = present")
	}
}

func TestYAMLRendererFileNoOp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	fr := &malcontent.FileReport{Path: "/test"}
	err := renderer.File(t.Context(), fr)
	if err != nil {
		t.Errorf("File() error: got = %v, want = nil", err)
	}

	if buf.Len() != 0 {
		t.Errorf("File() output: got = %q, want = empty", buf.String())
	}
}

func TestYAMLRendererSpecialCharacters(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
	}

	// Add file with special characters
	report.Files.Store("/bin/test:colon", &malcontent.FileReport{
		Path:      "/bin/test:colon",
		RiskScore: 1,
	})

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	// Should produce valid YAML despite special characters
	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output with special characters: got err = %v, want = nil", err)
	}
}

func TestYAMLRendererMultipleFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewYAML(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
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
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	var result Report
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}

	if len(result.Files) != 5 {
		t.Errorf("files: got = %d, want = 5", len(result.Files))
	}
}
