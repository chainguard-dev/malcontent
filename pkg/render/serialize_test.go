// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
	"gopkg.in/yaml.v3"
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
