// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"runtime"
	"slices"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// jsonRequireSame fails when got differs from want, showing where they part.
func jsonRequireSame(t *testing.T, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	from := max(0, i-40)
	t.Errorf("output differs at byte %d (got %d bytes, want %d):\ngot  = %q\nwant = %q",
		i, len(got), len(want), got[from:min(len(got), i+40)], want[from:min(len(want), i+40)])
}

func TestJSONWritesSanitizedReports(t *testing.T) {
	t.Parallel()
	files := xsync.NewMap[string, *malcontent.FileReport]()
	files.Store("/bin/b\n", &malcontent.FileReport{
		Path:        "/bin/b\n",
		ArchiveRoot: "/archive",
		FullPath:    "/archive/bin/b",
		RiskScore:   1,
		RiskLevel:   "LOW",
		Behaviors:   []*malcontent.Behavior{{ID: "net/connect\n", Description: " connects ", RiskScore: 1, RiskLevel: "LOW"}},
	})
	files.Store("/bin/a", &malcontent.FileReport{Path: "/bin/a", SHA256: "abc", Size: 3})
	files.Store("/bin/skipped", &malcontent.FileReport{Path: "/bin/skipped", Skipped: "data file"})
	files.Store("/bin/missing", nil)

	// Reports are keyed and sorted by sanitized path, lose their absolute
	// paths, and have their text trimmed. Skipped and missing reports are
	// left out.
	want := `{
    "Files": {
        "/bin/a": {
            "Path": "/bin/a",
            "SHA256": "abc",
            "Size": 3,
            "RiskScore": 0
        },
        "/bin/b": {
            "Path": "/bin/b",
            "SHA256": "",
            "Size": 0,
            "Behaviors": [
                {
                    "Description": "connects",
                    "RiskScore": 1,
                    "RiskLevel": "LOW",
                    "ID": "net/connect"
                }
            ],
            "RiskScore": 1,
            "RiskLevel": "LOW"
        }
    }
}
`
	var buf bytes.Buffer
	if err := NewJSON(&buf).Full(t.Context(), nil, &malcontent.Report{Files: files}); err != nil {
		t.Fatalf("Full: got err = %v, want = nil", err)
	}
	jsonRequireSame(t, buf.String(), want)
}

func TestJSONWritesFilesInChunks(t *testing.T) {
	t.Parallel()
	// The opening and the closing of the document are one write each, and
	// the file reports follow in writes of up to 32 reports.
	tests := []struct {
		name       string
		files      int
		wantWrites int
	}{
		{name: "no files", files: 0, wantWrites: 2},
		{name: "one file", files: 1, wantWrites: 3},
		{name: "32 files fill one chunk", files: 32, wantWrites: 3},
		{name: "33 files start a second chunk", files: 33, wantWrites: 4},
		{name: "64 files fill two chunks", files: 64, wantWrites: 4},
		{name: "293 files take ten chunks", files: 293, wantWrites: 12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			procs := runtime.GOMAXPROCS(0)
			rep, byKey := renderNumberedFiles(tt.files)
			w := &renderWriteLog{}
			if err := NewJSON(w).Full(t.Context(), nil, rep); err != nil {
				t.Fatalf("Full: got err = %v, want = nil", err)
			}
			if len(w.writes) != tt.wantWrites {
				t.Errorf("writes: got = %d, want = %d", len(w.writes), tt.wantWrites)
			}
			for i, p := range w.writes {
				if len(p) == 0 {
					t.Errorf("write %d: got = empty, want = bytes", i+1)
				}
			}
			want, err := json.MarshalIndent(Report{Files: byKey}, "", "    ")
			if err != nil {
				t.Fatalf("MarshalIndent: got err = %v, want = nil", err)
			}
			jsonRequireSame(t, w.String(), string(want)+"\n")
			if got := runtime.GOMAXPROCS(0); got != procs {
				t.Errorf("GOMAXPROCS after Full: got = %d, want = %d", got, procs)
			}
		})
	}
}

func TestJSONReturnsEncodingErrors(t *testing.T) {
	t.Parallel()
	// JSON has no form for NaN, so a report holding one cannot be encoded.
	bad := func(path string) *malcontent.FileReport {
		return &malcontent.FileReport{Path: path, PreviousRelPathScore: math.NaN()}
	}
	// withBad returns a scan report with n good files and one bad file that
	// sorts after them.
	withBad := func(n int) *malcontent.Report {
		rep, _ := renderNumberedFiles(n)
		rep.Files.Store("/z/bad", bad("/z/bad"))
		return rep
	}
	tests := []struct {
		name       string
		rep        *malcontent.Report
		wantWrites int
	}{
		{name: "bad diff writes nothing", rep: &malcontent.Report{Diff: renderDiff(nil, []*malcontent.FileReport{bad("/bin/added")}, nil)}, wantWrites: 0},
		{name: "bad report in the only chunk stops after the opening", rep: withBad(1), wantWrites: 1},
		{name: "bad report in a later chunk stops after the chunks before it", rep: withBad(39), wantWrites: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := &renderWriteLog{}
			if err := NewJSON(w).Full(t.Context(), nil, tt.rep); err == nil {
				t.Error("Full error: got = nil, want = an encoding error")
			}
			if len(w.writes) != tt.wantWrites {
				t.Errorf("writes: got = %d (%q), want = %d", len(w.writes), w.String(), tt.wantWrites)
			}
		})
	}
}

func TestSanitizedFilesKeepOneReportPerKey(t *testing.T) {
	t.Parallel()
	files := xsync.NewMap[string, *malcontent.FileReport]()
	// The last two keys are equal once sanitized and sort last.
	for _, key := range []string{"zz\n", "a", "zz "} {
		files.Store(key, &malcontent.FileReport{Path: "/p"})
	}
	got := sanitizedFiles(t.Context(), files)
	keys := make([]string, 0, len(got))
	for _, e := range got {
		keys = append(keys, e.key)
	}
	if want := []string{"a", "zz"}; !slices.Equal(keys, want) {
		t.Errorf("keys: got = %q, want = %q", keys, want)
	}
	// A dropped report must not stay reachable past the end of the result.
	for i, e := range got[len(got):cap(got)] {
		if e.fr != nil {
			t.Errorf("entry %d past the end: got = %+v, want = cleared", len(got)+i, e)
		}
	}
}

func TestJSONRendererEmpty(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
	}

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	// Verify valid JSON was generated
	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}
}

func TestJSONRendererWithFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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

	// Parse and verify JSON
	var result Report
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
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

func TestJSONRendererWithSkippedFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
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

func TestJSONRendererNilReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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

func TestJSONRendererCanceledContext(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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

func TestJSONRendererWithStats(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}

	// Stats should be present when enabled
	if result.Stats == nil {
		t.Error("stats with Stats=true: got = absent, want = present")
	}
}

func TestJSONRendererWithDiff(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
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

func TestJSONRendererScanningNoOp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	// Scanning should be a no-op for JSON renderer
	renderer.Scanning(t.Context(), "/some/path")

	if buf.Len() != 0 {
		t.Errorf("Scanning() output: got = %q, want = empty", buf.String())
	}
}

func TestJSONRendererDiffWithNilFiles(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

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
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output: got err = %v, want = nil", err)
	}

	if result.Diff == nil {
		t.Error("diff: got = absent, want = present")
	}
}

func TestJSONRendererFileNoOp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	fr := &malcontent.FileReport{Path: "/test"}
	err := renderer.File(t.Context(), fr)
	if err != nil {
		t.Errorf("File() error: got = %v, want = nil", err)
	}

	if buf.Len() != 0 {
		t.Errorf("File() output: got = %q, want = empty", buf.String())
	}
}

func TestJSONRendererSpecialCharacters(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	renderer := NewJSON(&buf)

	ctx := t.Context()
	cfg := &malcontent.Config{}
	report := &malcontent.Report{
		Files: xsync.NewMap[string, *malcontent.FileReport](),
	}

	// Add file with special characters
	report.Files.Store("/bin/test\"quote'", &malcontent.FileReport{
		Path:      "/bin/test\"quote'",
		RiskScore: 1,
	})

	err := renderer.Full(ctx, cfg, report)
	if err != nil {
		t.Fatalf("Full() error: got = %v, want = nil", err)
	}

	// Should produce valid JSON despite special characters
	var result Report
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("decode output with special characters: got err = %v, want = nil", err)
	}
}
