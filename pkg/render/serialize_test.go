// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
	"go.yaml.in/yaml/v3"
)

func TestSerializedRenderersIncludeStatsOnlyWhenRequested(t *testing.T) {
	t.Parallel()
	formats := []struct {
		name        string
		newRenderer func(io.Writer) malcontent.Renderer
		decode      func([]byte, *Report) error
	}{
		{
			name:        "json",
			newRenderer: func(w io.Writer) malcontent.Renderer { return NewJSON(w) },
			decode:      func(b []byte, r *Report) error { return json.Unmarshal(b, r) },
		},
		{
			name:        "yaml",
			newRenderer: func(w io.Writer) malcontent.Renderer { return NewYAML(w) },
			decode:      func(b []byte, r *Report) error { return yaml.Unmarshal(b, r) },
		},
	}
	tests := []struct {
		name      string
		cfg       *malcontent.Config
		diff      bool
		wantStats bool
	}{
		{name: "nil config omits stats", cfg: nil},
		{name: "stats disabled omits stats", cfg: &malcontent.Config{}},
		{name: "stats enabled includes stats", cfg: &malcontent.Config{Stats: true}, wantStats: true},
		{name: "stats enabled for a diff omits stats", cfg: &malcontent.Config{Stats: true}, diff: true},
	}
	for _, f := range formats {
		for _, tt := range tests {
			t.Run(f.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				files := xsync.NewMap[string, *malcontent.FileReport]()
				files.Store("/bin/tool", renderBehaviorReport())
				rep := &malcontent.Report{Files: files}
				if tt.diff {
					rep.Diff = renderDiff(nil, []*malcontent.FileReport{{Path: "/bin/added", RiskScore: 2}}, nil)
				}

				var buf bytes.Buffer
				if err := f.newRenderer(&buf).Full(t.Context(), tt.cfg, rep); err != nil {
					t.Fatalf("Full: got err = %v, want = nil", err)
				}
				var got Report
				if err := f.decode(buf.Bytes(), &got); err != nil {
					t.Fatalf("decode: got err = %v, want = nil", err)
				}
				if (got.Stats != nil) != tt.wantStats {
					t.Fatalf("Stats present: got = %v, want = %v", got.Stats != nil, tt.wantStats)
				}
				if tt.wantStats && (got.Stats.ProcessedFiles != 1 || got.Stats.TotalBehaviors != 1) {
					t.Errorf("Stats: got = %+v, want ProcessedFiles=1 TotalBehaviors=1", got.Stats)
				}
			})
		}
	}
}

func TestSerializedRenderersStopCollectingWhenCanceled(t *testing.T) {
	t.Parallel()
	formats := []struct {
		name        string
		newRenderer func(io.Writer) malcontent.Renderer
		decode      func([]byte, *Report) error
	}{
		{
			name:        "json",
			newRenderer: func(w io.Writer) malcontent.Renderer { return NewJSON(w) },
			decode:      func(b []byte, r *Report) error { return json.Unmarshal(b, r) },
		},
		{
			name:        "yaml",
			newRenderer: func(w io.Writer) malcontent.Renderer { return NewYAML(w) },
			decode:      func(b []byte, r *Report) error { return yaml.Unmarshal(b, r) },
		},
	}
	for _, f := range formats {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			files := xsync.NewMap[string, *malcontent.FileReport]()
			reports := make([]*malcontent.FileReport, 0, 3)
			for _, path := range []string{"/bin/a", "/bin/b", "/bin/c"} {
				fr := &malcontent.FileReport{Path: path, FullPath: "/root" + path, RiskScore: 1}
				reports = append(reports, fr)
				files.Store(path, fr)
			}
			// Full checks the context once, then once per report, so the
			// second report finds it canceled.
			ctx := &markdownCountdownCtx{Context: t.Context(), allowed: 2}
			var buf bytes.Buffer
			err := f.newRenderer(&buf).Full(ctx, nil, &malcontent.Report{Files: files})
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Full error: got = %v, want = %v", err, context.Canceled)
			}
			if buf.Len() != 0 {
				t.Errorf("output: got = %q, want = empty instead of a partial report", buf.String())
			}
			sanitized := 0
			for _, fr := range reports {
				if fr.FullPath == "" {
					sanitized++
				}
			}
			if sanitized != 1 {
				t.Errorf("reports sanitized: got = %d, want = 1", sanitized)
			}
		})
	}
}

// serializeFormats are the renderers that write a whole report as data, with
// a decoder for each.
var serializeFormats = []struct {
	name        string
	newRenderer func(io.Writer) malcontent.Renderer
	decode      func([]byte, *Report) error
}{
	{
		name:        "json",
		newRenderer: func(w io.Writer) malcontent.Renderer { return NewJSON(w) },
		decode:      func(b []byte, r *Report) error { return json.Unmarshal(b, r) },
	},
	{
		name:        "yaml",
		newRenderer: func(w io.Writer) malcontent.Renderer { return NewYAML(w) },
		decode:      func(b []byte, r *Report) error { return yaml.Unmarshal(b, r) },
	},
}

// serializeRender renders rep with f and decodes the output.
func serializeRender(t *testing.T, newRenderer func(io.Writer) malcontent.Renderer, decode func([]byte, *Report) error, rep *malcontent.Report) (string, Report) {
	t.Helper()
	var buf bytes.Buffer
	if err := newRenderer(&buf).Full(t.Context(), nil, rep); err != nil {
		t.Fatalf("Full: got err = %v, want = nil", err)
	}
	var got Report
	if err := decode(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: got err = %v, want = nil", err)
	}
	return buf.String(), got
}

func TestSerializedRenderersKeepFilesWhoseKeysCollide(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		keys []string
		// want maps each written key to the risk score of the report under it.
		want map[string]int
	}{
		{
			name: "distinct keys are unchanged",
			keys: []string{"/a", "/b"},
			want: map[string]int{"/a": 0, "/b": 1},
		},
		{
			name: "newline and space: the key sanitizing leaves alone keeps it",
			keys: []string{"/x/evil\nsh", "/x/evil sh"},
			want: map[string]int{"/x/evil sh (2)": 0, "/x/evil sh": 1},
		},
		{
			name: "trailing space",
			keys: []string{"/x/evil ", "/x/evil"},
			want: map[string]int{"/x/evil (2)": 0, "/x/evil": 1},
		},
		{
			name: "invalid UTF-8 bytes take suffixes in byte order",
			keys: []string{"/x/e\xffvil", "/x/e\xfevil"},
			want: map[string]int{"/x/e�vil (2)": 0, "/x/e�vil": 1},
		},
		{
			name: "BiDi override",
			keys: []string{"/x/e\xe2\x80\xaevil", "/x/evil"},
			want: map[string]int{"/x/evil (2)": 0, "/x/evil": 1},
		},
		{
			name: "suffix skips a key already in use",
			keys: []string{"/a\n", "/a", "/a (2)", "/a\r"},
			want: map[string]int{"/a (3)": 0, "/a": 1, "/a (2)": 2, "/a (4)": 3},
		},
	}
	for _, f := range serializeFormats {
		for _, tt := range tests {
			t.Run(f.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				var first string
				// Map iteration order varies from map to map, so several
				// renders show whether the keys depend on it.
				for range 8 {
					files := xsync.NewMap[string, *malcontent.FileReport]()
					for i, key := range tt.keys {
						files.Store(key, &malcontent.FileReport{Path: key, RiskScore: i})
					}
					out, got := serializeRender(t, f.newRenderer, f.decode, &malcontent.Report{Files: files})
					gotScores := make(map[string]int, len(got.Files))
					for key, fr := range got.Files {
						gotScores[key] = fr.RiskScore
					}
					if !maps.Equal(gotScores, tt.want) {
						t.Fatalf("files by key: got = %v, want = %v", gotScores, tt.want)
					}
					if first == "" {
						first = out
					} else if out != first {
						t.Fatalf("output changed between renders:\nfirst = %q\nlater = %q", first, out)
					}
				}
			})
		}
	}
}

func TestSerializedRenderersSanitizeDiffEntries(t *testing.T) {
	t.Parallel()
	// The first key holds a BiDi override, so it sanitizes to the second.
	evil := "/x/e\xe2\x80\xaevil"
	diff := func() *malcontent.DiffReport {
		return renderDiff(
			[]*malcontent.FileReport{{Path: "/old\nname", ArchiveRoot: "/tmp/root", FullPath: "/tmp/root/old", RiskScore: 1}},
			[]*malcontent.FileReport{
				{Path: evil, ArchiveRoot: "/tmp/root", FullPath: "/tmp/root/x/evil", RiskScore: 2},
				{Path: "/x/evil", RiskScore: 3},
			},
			[]*malcontent.FileReport{{Path: "/new\xff", PreviousPath: "/prev\nname", RiskScore: 4, Behaviors: []*malcontent.Behavior{
				{ID: "net/connect\n", Description: "connects\xe2\x80\xae", DiffAdded: true},
			}}},
		)
	}
	for _, f := range serializeFormats {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			out, got := serializeRender(t, f.newRenderer, f.decode, &malcontent.Report{Diff: diff()})
			if got.Diff == nil {
				t.Fatalf("Diff: got = nil, want = present in %q", out)
			}
			for _, absent := range []string{"/tmp/root", "\xe2\x80\xae"} {
				if strings.Contains(out, absent) {
					t.Errorf("output: got %q in %q, want = absent", absent, out)
				}
			}
			removed := got.Diff.Removed.Oldest()
			if removed == nil || removed.Key != "/old name" || removed.Value.Path != "/old name" {
				t.Errorf("removed entry: got = %+v, want key and path %q", removed, "/old name")
			}
			var added []string
			for p := got.Diff.Added.Oldest(); p != nil; p = p.Next() {
				added = append(added, fmt.Sprintf("%s=%d", p.Key, p.Value.RiskScore))
			}
			if want := []string{"/x/evil (2)=2", "/x/evil=3"}; !slices.Equal(added, want) {
				t.Errorf("added entries: got = %q, want = %q", added, want)
			}
			modified := got.Diff.Modified.Oldest()
			if modified == nil {
				t.Fatalf("modified entry: got = nil, want = present in %q", out)
			}
			if modified.Key != "/new�" || modified.Value.Path != "/new�" || modified.Value.PreviousPath != "/prev name" {
				t.Errorf("modified entry: got key=%q path=%q previous=%q, want key and path %q and previous %q",
					modified.Key, modified.Value.Path, modified.Value.PreviousPath, "/new�", "/prev name")
			}
			if bh := modified.Value.Behaviors[0]; bh.ID != "net/connect" || bh.Description != "connects" {
				t.Errorf("modified behavior: got ID=%q description=%q, want %q and %q", bh.ID, bh.Description, "net/connect", "connects")
			}
		})
	}
}
