// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestLoad(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		data            []byte
		wantErr         bool
		wantErrText     string // The exact error, when set
		wantErrIs       error  // An error the returned one wraps, when set
		wantNonNilFiles bool   // Only check FileReports != nil for these
	}{
		{
			name:            "valid empty report",
			data:            []byte(`{"Files":{}}`),
			wantErr:         false,
			wantNonNilFiles: true,
		},
		{
			name: "valid report with files",
			data: []byte(`{
				"Files": {
					"/bin/ls": {
						"Path": "/bin/ls",
						"RiskScore": 1,
						"RiskLevel": "low"
					}
				}
			}`),
			wantErr:         false,
			wantNonNilFiles: true,
		},
		{
			name:    "invalid json",
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte(``),
			wantErr: true,
		},
		{
			name:      "null is not a report",
			data:      []byte(`null`),
			wantErr:   true,
			wantErrIs: errNoFiles,
		},
		{
			name:      "array is not a report",
			data:      []byte(`[]`),
			wantErr:   true,
			wantErrIs: errNoFiles,
		},
		{
			name:            "empty object",
			data:            []byte(`{}`),
			wantErr:         false,
			wantNonNilFiles: false,
		},
		{
			name: "report with behaviors",
			data: []byte(`{
				"Files": {
					"/usr/bin/curl": {
						"Path": "/usr/bin/curl",
						"RiskScore": 2,
						"RiskLevel": "medium",
						"Behaviors": [
							{
								"ID": "net/http",
								"Description": "Makes HTTP requests"
							}
						]
					}
				}
			}`),
			wantErr:         false,
			wantNonNilFiles: true,
		},
		{
			name:            "report with no behaviors",
			data:            []byte(`{"Files":{"/a":{"Path":"/a","Behaviors":[]}}}`),
			wantErr:         false,
			wantNonNilFiles: true,
		},
		{
			name:        "null file report",
			data:        []byte(`{"Files":{"/a":null}}`),
			wantErr:     true,
			wantErrText: `report entry "/a" is empty`,
		},
		{
			name:        "null behavior",
			data:        []byte(`{"Files":{"/a":{"Path":"/a","Behaviors":[null]}}}`),
			wantErr:     true,
			wantErrText: `report entry "/a" has an empty behavior`,
		},
		{
			name:        "first damaged entry by key is named",
			data:        []byte(`{"Files":{"/c":null,"/a":{"Path":"/a","Behaviors":[null]},"/b":{"Path":"/b"}}}`),
			wantErr:     true,
			wantErrText: `report entry "/a" has an empty behavior`,
		},
		{
			name:        "control characters in a damaged key are escaped",
			data:        []byte(`{"Files":{"/a\u001b[2J":null}}`),
			wantErr:     true,
			wantErrText: `report entry "/a\x1b[2J" is empty`,
		},
		{
			name:      "diff report",
			data:      []byte(`{"Diff":{"Added":{"/a":{"Path":"/a","RiskScore":4}}}}`),
			wantErr:   true,
			wantErrIs: errDiffReport,
		},
		{
			name:      "diff report that also holds files",
			data:      []byte(`{"Diff":{},"Files":{"/a":{"Path":"/a"}}}`),
			wantErr:   true,
			wantErrIs: errDiffReport,
		},
		{
			name:            "null diff is no diff",
			data:            []byte(`{"Diff":null,"Files":{"/a":{"Path":"/a"}}}`),
			wantNonNilFiles: true,
		},
		{
			name:      "object without files",
			data:      []byte(`{"anything":1}`),
			wantErr:   true,
			wantErrIs: errNoFiles,
		},
		{
			name:      "null files",
			data:      []byte(`{"Files":null}`),
			wantErr:   true,
			wantErrIs: errNoFiles,
		},
		{
			name: "statistics only, as for a scan that found nothing",
			data: []byte(`{"Stats":{"ProcessedFiles":3}}`),
		},
		{
			name:      "statistics and another member",
			data:      []byte(`{"Stats":{},"anything":1}`),
			wantErr:   true,
			wantErrIs: errNoFiles,
		},
		{
			name:            "byte order mark before a report",
			data:            []byte("\ufeff" + `{"Files":{"/a":{"Path":"/a"}}}`),
			wantNonNilFiles: true,
		},
		{
			name:            "entry whose path differs from its key",
			data:            []byte(`{"Files":{"/a (2)":{"Path":"/a"}}}`),
			wantNonNilFiles: true,
		},
		{
			name:            "entry with an empty path",
			data:            []byte(`{"Files":{"/a":{"Path":""}}}`),
			wantNonNilFiles: true,
		},
		{
			name:            "lowest and highest risk levels",
			data:            fmt.Appendf(nil, `{"Files":{"/a":{"Path":"/a","RiskScore":%d,"PreviousRiskScore":%d,"Behaviors":[{"ID":"x","RiskScore":%[2]d},{"ID":"y","RiskScore":%[1]d}]}}}`, HARMLESS, CRITICAL),
			wantNonNilFiles: true,
		},
		{
			name:        "file risk above the highest level",
			data:        fmt.Appendf(nil, `{"Files":{"/a":{"Path":"/a","RiskScore":%d}}}`, CRITICAL+1),
			wantErr:     true,
			wantErrText: fmt.Sprintf(`report entry "/a" has unknown risk score %d`, CRITICAL+1),
		},
		{
			name:        "file risk of the invalid level",
			data:        fmt.Appendf(nil, `{"Files":{"/a":{"Path":"/a","RiskScore":%d}}}`, INVALID),
			wantErr:     true,
			wantErrText: fmt.Sprintf(`report entry "/a" has unknown risk score %d`, INVALID),
		},
		{
			name:        "previous risk above the highest level",
			data:        fmt.Appendf(nil, `{"Files":{"/a":{"Path":"/a","PreviousRiskScore":%d}}}`, CRITICAL+1),
			wantErr:     true,
			wantErrText: fmt.Sprintf(`report entry "/a" has unknown previous risk score %d`, CRITICAL+1),
		},
		{
			name:        "behavior risk below the lowest level",
			data:        fmt.Appendf(nil, `{"Files":{"/a":{"Path":"/a","Behaviors":[{"ID":"net/http","RiskScore":%d}]}}}`, INVALID-1),
			wantErr:     true,
			wantErrText: fmt.Sprintf(`report entry "/a" has behavior "net/http" with unknown risk score %d`, INVALID-1),
		},
		{
			name:        "override risk above the highest level",
			data:        fmt.Appendf(nil, `{"Files":{"/a":{"Path":"/a","Overrides":[{"ID":"fp/x","RiskScore":%d}]}}}`, CRITICAL+1),
			wantErr:     true,
			wantErrText: fmt.Sprintf(`report entry "/a" has override "fp/x" with unknown risk score %d`, CRITICAL+1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Load(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErrText != "" && err.Error() != tt.wantErrText {
				t.Errorf("Load() error = %q, want %q", err, tt.wantErrText)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("Load() error = %v, want %v", err, tt.wantErrIs)
			}

			if !tt.wantErr && tt.wantNonNilFiles && got.FileReports == nil {
				t.Error("Load() returned report with nil FileReports map")
			}
		})
	}
}

func TestLoadYAML(t *testing.T) {
	t.Parallel()
	// The shape the YAML renderer writes: lowercase keys, files under "files".
	data := []byte(`files:
    /usr/bin/curl:
        path: /usr/bin/curl
        riskscore: 2
        risklevel: MEDIUM
        behaviors:
            - description: Makes HTTP requests
              riskscore: 2
              id: net/http
`)
	got, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	fr, ok := got.FileReports["/usr/bin/curl"]
	if !ok {
		t.Fatalf("Load() files = %v, want /usr/bin/curl", got.FileReports)
	}
	if fr.Path != "/usr/bin/curl" || fr.RiskScore != 2 || fr.RiskLevel != "MEDIUM" {
		t.Errorf("Load() file = %+v, want path /usr/bin/curl, risk 2 MEDIUM", fr)
	}
	if len(fr.Behaviors) != 1 || fr.Behaviors[0].ID != "net/http" || fr.Behaviors[0].RiskScore != 2 {
		t.Errorf("Load() behaviors = %+v, want one net/http behavior with risk 2", fr.Behaviors)
	}

	// YAML that holds no file reports is not a report.
	for _, data := range []string{"this is not a report", "files:\n", "- a\n- b\n"} {
		if _, err := Load([]byte(data)); err == nil {
			t.Errorf("Load(%q) error = nil, want an error", data)
		}
	}

	// A report with an empty file report or behavior is damaged.
	for _, data := range []string{
		"files:\n    /a:\n",
		"files:\n    /a:\n        path: /a\n        behaviors:\n            - null\n",
	} {
		if _, err := Load([]byte(data)); err == nil || !strings.Contains(err.Error(), `"/a"`) {
			t.Errorf("Load(%q) error = %v, want an error naming \"/a\"", data, err)
		}
	}
}

func TestLoadYAMLShapes(t *testing.T) {
	t.Parallel()
	// meta returns an entry for /a whose meta mapping holds n keys.
	meta := func(n int) string {
		var b strings.Builder
		b.WriteString("files:\n    /a:\n        path: /a\n        meta:\n")
		for i := range n {
			fmt.Fprintf(&b, "            k%d: v\n", i)
		}
		return b.String()
	}
	long := "/opt/" + strings.Repeat("deep/", 40) + "file"
	syntaxErr := func(err error) bool {
		var se *json.SyntaxError
		return errors.As(err, &se)
	}
	tests := []struct {
		name      string
		data      string
		wantFiles []string // The keys of the loaded files, when there is no error
		wantErr   string   // A substring of the error, when set
		wantErrIs error
		match     func(error) bool
	}{
		{
			name:      "statistics only, as the renderer writes for a scan that found nothing",
			data:      "stats: {}\n\n",
			wantFiles: []string{},
		},
		{
			name:      "statistics with values",
			data:      "stats:\n    processedfiles: 3\n    skippedfiles: 1\n",
			wantFiles: []string{},
		},
		{
			name:      "empty files mapping",
			data:      "files: {}\n",
			wantFiles: []string{},
		},
		{
			name:      "byte order mark before a report",
			data:      "\ufefffiles:\n    /a:\n        path: /a\n",
			wantFiles: []string{"/a"},
		},
		{
			name:      "file named like a merge key",
			data:      "files:\n    <<:\n        path: <<\n",
			wantFiles: []string{"<<"},
		},
		{
			name:      "long path written as an explicit key",
			data:      "files:\n    ? " + long + "\n    : path: " + long + "\n",
			wantFiles: []string{long},
		},
		{
			name:      "nested mapping at the key limit",
			data:      meta(maxEntryKeys),
			wantFiles: []string{"/a"},
		},
		{
			name:      "diff report",
			data:      "diff:\n    added:\n        /a:\n            path: /a\n",
			wantErrIs: errDiffReport,
		},
		{
			name:      "null files",
			data:      "files:\n",
			wantErrIs: errNoFiles,
		},
		{
			name:      "mapping without files",
			data:      "anything: 1\n",
			wantErrIs: errNoFiles,
		},
		{
			name:    "files that are not a mapping",
			data:    "files:\n    - /a\n",
			wantErr: "files is not a mapping",
		},
		{
			name:    "syntax error keeps the YAML error",
			data:    "files:\n    /a: [\n",
			wantErr: "yaml: ",
		},
		{
			name:    "duplicate entry",
			data:    "files:\n    /a:\n        path: /a\n    /a:\n        path: /a\n",
			wantErr: `report entry "/a" is defined more than once`,
		},
		{
			name:    "duplicate report key",
			data:    "files:\n    /a:\n        path: /a\nfiles:\n    /b:\n        path: /b\n",
			wantErr: `report key "files" is defined more than once`,
		},
		{
			name:    "duplicate key within an entry",
			data:    "files:\n    /a:\n        path: /a\n        path: /a\n",
			wantErr: `report entry "/a": `,
		},
		{
			name:    "entry that is an alias",
			data:    "files:\n    /a: &e\n        path: /a\n    /b: *e\n",
			wantErr: `report entry "/b": line 4: aliases are not supported`,
		},
		{
			name:    "alias within an entry",
			data:    "files:\n    /a:\n        path: /a\n        behaviors:\n            - &b\n              id: x\n            - *b\n",
			wantErr: `report entry "/a": line 7: aliases are not supported`,
		},
		{
			name:    "nested mapping over the key limit",
			data:    meta(maxEntryKeys + 1),
			wantErr: fmt.Sprintf(`report entry "/a": line 5: mapping holds more than %d keys`, maxEntryKeys),
		},
		{
			name:  "text that is not a report keeps the JSON error",
			data:  "this is not a report",
			match: syntaxErr,
		},
		{
			name:  "sequence keeps the JSON error",
			data:  "- a\n- b\n",
			match: syntaxErr,
		},
		{
			name:  "empty input keeps the JSON error",
			data:  "",
			match: syntaxErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Load([]byte(tt.data))
			if tt.wantFiles != nil {
				if err != nil {
					t.Fatalf("Load() error = %v, want nil", err)
				}
				if keys := slices.Sorted(maps.Keys(got.FileReports)); !slices.Equal(keys, tt.wantFiles) {
					t.Errorf("Load() files = %q, want %q", keys, tt.wantFiles)
				}
				return
			}
			switch {
			case err == nil:
				t.Fatalf("Load() error = nil, want an error")
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("Load() error = %q, want it to hold %q", err, tt.wantErr)
			case tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs):
				t.Errorf("Load() error = %v, want %v", err, tt.wantErrIs)
			case tt.match != nil && !tt.match(err):
				t.Errorf("Load() error = %v (%T), want a JSON syntax error", err, err)
			}
		})
	}
}

// TestLoadRejectsNonFiniteFloats sets each float field of a file report and
// of a behavior to NaN and to each infinity, which only YAML can spell. It
// finds the fields by reflection, so a new one is covered too.
func TestLoadRejectsNonFiniteFloats(t *testing.T) {
	t.Parallel()
	floats := func(v any) []string {
		var names []string
		for f := range reflect.TypeOf(v).Fields() {
			if k := f.Type.Kind(); k == reflect.Float32 || k == reflect.Float64 {
				names = append(names, strings.ToLower(f.Name))
			}
		}
		return names
	}
	values := []string{".nan", ".inf", "-.inf"}
	fileFloats, behaviorFloats := floats(malcontent.FileReport{}), floats(malcontent.Behavior{})
	docs := make([]string, 0, len(values)*(len(fileFloats)+len(behaviorFloats)))
	for _, value := range values {
		for _, name := range fileFloats {
			docs = append(docs, fmt.Sprintf("files:\n    /a:\n        path: /a\n        %s: %s\n", name, value))
		}
		for _, name := range behaviorFloats {
			docs = append(docs, fmt.Sprintf("files:\n    /a:\n        path: /a\n        behaviors:\n            - id: x\n              %s: %s\n", name, value))
		}
	}
	if len(docs) == 0 {
		t.Fatal("found no float fields to check")
	}
	for _, doc := range docs {
		if _, err := Load([]byte(doc)); err == nil || !strings.Contains(err.Error(), `report entry "/a"`) {
			t.Errorf("Load(%q) error = %v, want an error naming \"/a\"", doc, err)
		}
	}
}

func TestLoadClearsDiffMarks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
	}{
		{
			name: "JSON",
			data: `{"Files":{"/a":{"Path":"/a","Behaviors":[{"ID":"x","DiffAdded":true},{"ID":"y","DiffRemoved":true}],"Overrides":[{"ID":"o","DiffAdded":true,"DiffRemoved":true}]}}}`,
		},
		{
			name: "YAML",
			data: "files:\n    /a:\n        path: /a\n        behaviors:\n            - id: x\n              diffadded: true\n            - id: y\n              diffremoved: true\n        overrides:\n            - id: o\n              diffadded: true\n              diffremoved: true\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Load([]byte(tt.data))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			fr := got.FileReports["/a"]
			bs := slices.Concat(fr.Behaviors, fr.Overrides)
			if len(bs) != 3 {
				t.Fatalf("Load() behaviors and overrides = %d, want 3", len(bs))
			}
			for _, b := range bs {
				if b.DiffAdded || b.DiffRemoved {
					t.Errorf("Load() behavior %q: DiffAdded = %v, DiffRemoved = %v, want both false", b.ID, b.DiffAdded, b.DiffRemoved)
				}
			}
		})
	}
}

// loadTestPath returns the path of the i-th file of a report built for a
// test: paths of one length that share a long prefix, as a package's do.
func loadTestPath(i int) string {
	return fmt.Sprintf("/usr/lib/python3.12/site-packages/pkg%04d/module_%06d.py", i%1000, i)
}

// loadTestYAML returns a YAML report of n files in the renderer's layout.
func loadTestYAML(n int) []byte {
	var b strings.Builder
	b.WriteString("files:\n")
	for i := range n {
		p := loadTestPath(i)
		fmt.Fprintf(&b, "    %s:\n        path: %s\n        sha256: \"\"\n        size: 0\n        riskscore: 1\n", p, p)
	}
	return []byte(b.String())
}

// loadTestJSON returns a JSON report of n files.
func loadTestJSON(tb testing.TB, n int) []byte {
	tb.Helper()
	files := make(map[string]*malcontent.FileReport, n)
	for i := range n {
		p := loadTestPath(i)
		files[p] = &malcontent.FileReport{Path: p, RiskScore: 1}
	}
	data, err := json.Marshal(malcontent.ScanResult{FileReports: files})
	if err != nil {
		tb.Fatalf("json.Marshal: %v", err)
	}
	return data
}

// TestLoadYAMLScalesLinearly guards against loading time that grows with
// the square of the number of files, as decoding the files mapping in one
// piece does: eight times the files must take far less than 64 times as
// long. Each size keeps its fastest of several loads to damp noise.
func TestLoadYAMLScalesLinearly(t *testing.T) {
	t.Parallel()
	const (
		small    = 2000
		factor   = 8
		maxRatio = 24 // between linear (8) and quadratic (64) growth
		runs     = 3
	)
	fastest := func(data []byte) time.Duration {
		best := time.Duration(math.MaxInt64)
		for range runs {
			start := time.Now()
			if _, err := Load(data); err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	short, long := fastest(loadTestYAML(small)), fastest(loadTestYAML(small*factor))
	if ratio := float64(long) / float64(max(short, time.Microsecond)); ratio > maxRatio {
		t.Errorf("Load() of %d files took %v, %.1f times the %v of %d files, want at most %d times", small*factor, long, ratio, short, small, maxRatio)
	}
}

func BenchmarkLoad(b *testing.B) {
	const n = 10000
	for _, bm := range []struct {
		name string
		data []byte
	}{
		{"JSON", loadTestJSON(b, n)},
		{"YAML", loadTestYAML(n)},
	} {
		b.Run(bm.name, func(b *testing.B) {
			b.SetBytes(int64(len(bm.data)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Load(bm.data); err != nil {
					b.Fatalf("Load() error = %v", err)
				}
			}
		})
	}
}

func TestExtractTmpRoot(t *testing.T) {
	t.Parallel()
	// oneOf lists the acceptable results when several files match, because
	// map iteration order decides which match is returned.
	tests := []struct {
		name  string
		files map[string]*malcontent.FileReport
		want  string
		oneOf []string
	}{
		{
			name:  "empty files",
			files: map[string]*malcontent.FileReport{},
			want:  "",
		},
		{
			name: "no temp paths",
			files: map[string]*malcontent.FileReport{
				"/bin/ls": {Path: "/bin/ls"},
			},
			want: "",
		},
		{
			name: "with /tmp/ path",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "/tmp/abc123/xyz789/T/extract/file"},
			},
			want: "/tmp/abc123/xyz789/T/extract",
		},
		{
			name: "with /var/folders/ path (macOS)",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "/var/folders/ab/cd123456/T/extract123/file.txt"},
			},
			want: "/var/folders/ab/cd123456/T/extract123",
		},
		{
			name: "with /private/var/folders/ path",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "/private/var/folders/xy/z9876543/T/temp_dir/file"},
			},
			want: "/private/var/folders/xy/z9876543/T/temp_dir",
		},
		{
			name: "with /private/tmp/ path",
			files: map[string]*malcontent.FileReport{
				"key": {Path: "/private/tmp/abc/def/T/ghi/file"},
			},
			want: "/private/tmp/abc/def/T/ghi",
		},
		{
			name: "nil file report",
			files: map[string]*malcontent.FileReport{
				"key": nil,
			},
			want: "",
		},
		{
			name: "empty path",
			files: map[string]*malcontent.FileReport{
				"key": {Path: ""},
			},
			want: "",
		},
		{
			name: "multiple files returns one match",
			files: map[string]*malcontent.FileReport{
				"key1": {Path: "/tmp/aaa/bbb/T/ccc/file1"},
				"key2": {Path: "/tmp/xxx/yyy/T/zzz/file2"},
			},
			oneOf: []string{"/tmp/aaa/bbb/T/ccc", "/tmp/xxx/yyy/T/zzz"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ExtractTmpRoot(tt.files)

			if len(tt.oneOf) > 0 {
				if !slices.Contains(tt.oneOf, got) {
					t.Errorf("ExtractTmpRoot() = %q, want one of %v", got, tt.oneOf)
				}
				return
			}

			if got != tt.want {
				t.Errorf("ExtractTmpRoot() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCleanReportPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		tmpRoot  string
		imageURI string
		want     string
	}{
		{
			name:     "empty path",
			path:     "",
			tmpRoot:  "",
			imageURI: "",
			want:     "",
		},
		{
			name:     "path already has image URI",
			path:     "cgr.dev/image:tag ∴ /bin/file",
			tmpRoot:  "/tmp/extract",
			imageURI: "cgr.dev/image:tag",
			want:     "cgr.dev/image:tag ∴ /bin/file",
		},
		{
			name:     "remove tmp root",
			path:     "/tmp/abc123/xyz/T/extract/bin/ls",
			tmpRoot:  "/tmp/abc123/xyz/T/extract",
			imageURI: "",
			want:     "/bin/ls",
		},
		{
			name:     "path without tmp root",
			path:     "/usr/bin/curl",
			tmpRoot:  "/tmp/extract",
			imageURI: "",
			want:     "/usr/bin/curl",
		},
		{
			name:     "relative path gets leading slash",
			path:     "bin/file",
			tmpRoot:  "",
			imageURI: "",
			want:     "/bin/file",
		},
		{
			name:     "path with temp pattern",
			path:     "/var/folders/ab/cd/T/extract/file",
			tmpRoot:  "",
			imageURI: "",
			want:     "/file",
		},
		{
			name:     "already clean absolute path",
			path:     "/bin/sh",
			tmpRoot:  "",
			imageURI: "",
			want:     "/bin/sh",
		},
		{
			name:     "image URI prefix preserved",
			path:     "registry.io/image ∴ /app/main",
			tmpRoot:  "",
			imageURI: "registry.io/image",
			want:     "registry.io/image ∴ /app/main",
		},
		{
			name:     "temporary root that only prefixes a longer directory name is kept",
			path:     "/scratch/extract10/bin/ls",
			tmpRoot:  "/scratch/extract",
			imageURI: "",
			want:     "/scratch/extract10/bin/ls",
		},
		{
			name:     "temporary root of another extraction does not cut a name short",
			path:     "/tmp/a/b/T/mal10/usr/bin/y",
			tmpRoot:  "/tmp/a/b/T/mal1",
			imageURI: "",
			want:     "/usr/bin/y",
		},
		{
			name:     "temporary root equal to the path",
			path:     "/scratch/extract",
			tmpRoot:  "/scratch/extract",
			imageURI: "",
			want:     "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CleanReportPath(tt.path, tt.tmpRoot, tt.imageURI)
			if got != tt.want {
				t.Errorf("CleanReportPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatReportKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		tmpRoot  string
		imageURI string
		want     string
	}{
		{
			name:     "empty path",
			path:     "",
			tmpRoot:  "",
			imageURI: "",
			want:     "",
		},
		{
			name:     "path with image URI prefix",
			path:     "cgr.dev/image:tag ∴ /bin/file",
			tmpRoot:  "",
			imageURI: "cgr.dev/image:tag",
			want:     "cgr.dev/image:tag ∴ /bin/file",
		},
		{
			name:     "format with image URI",
			path:     "/tmp/extract/bin/ls",
			tmpRoot:  "/tmp/extract",
			imageURI: "registry.io/image:v1",
			want:     "registry.io/image:v1 ∴ /bin/ls",
		},
		{
			name:     "format without image URI",
			path:     "/tmp/extract/usr/bin/curl",
			tmpRoot:  "/tmp/extract",
			imageURI: "",
			want:     "/usr/bin/curl",
		},
		{
			name:     "clean path without tmp root",
			path:     "/bin/sh",
			tmpRoot:  "",
			imageURI: "",
			want:     "/bin/sh",
		},
		{
			name:     "relative path gets leading slash",
			path:     "app/main",
			tmpRoot:  "",
			imageURI: "",
			want:     "/app/main",
		},
		{
			name:     "path with temp pattern",
			path:     "/var/folders/ab/cd/T/xyz/file.txt",
			tmpRoot:  "",
			imageURI: "",
			want:     "/file.txt",
		},
		{
			name:     "path with temp pattern and image URI",
			path:     "/private/tmp/a/b/T/c/bin/app",
			tmpRoot:  "",
			imageURI: "ghcr.io/org/app:latest",
			want:     "ghcr.io/org/app:latest ∴ /bin/app",
		},
		{
			name:     "temporary root that only prefixes a longer directory name is kept",
			path:     "/scratch/extract10/bin/ls",
			tmpRoot:  "/scratch/extract",
			imageURI: "registry.io/image:v1",
			want:     "registry.io/image:v1 ∴ /scratch/extract10/bin/ls",
		},
		{
			name:     "temporary root of another extraction does not cut a name short",
			path:     "/tmp/a/b/T/mal10/usr/bin/y",
			tmpRoot:  "/tmp/a/b/T/mal1",
			imageURI: "",
			want:     "/usr/bin/y",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := FormatReportKey(tt.path, tt.tmpRoot, tt.imageURI)
			if got != tt.want {
				t.Errorf("FormatReportKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadRoundTrip(t *testing.T) {
	t.Parallel()
	original := malcontent.ScanResult{
		FileReports: map[string]*malcontent.FileReport{
			"/bin/ls": {
				Path:      "/bin/ls",
				RiskScore: 1,
				RiskLevel: "low",
			},
			"/usr/bin/curl": {
				Path:      "/usr/bin/curl",
				RiskScore: 2,
				RiskLevel: "medium",
			},
		},
	}

	// marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// load the JSON data
	loaded, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// verify contents
	if len(loaded.FileReports) != len(original.FileReports) {
		t.Errorf("loaded %d files, want %d", len(loaded.FileReports), len(original.FileReports))
	}

	for key, origFR := range original.FileReports {
		loadedFR, ok := loaded.FileReports[key]
		if !ok {
			t.Errorf("missing file %q in loaded report", key)
			continue
		}

		if loadedFR.Path != origFR.Path {
			t.Errorf("file %q: path = %q, want %q", key, loadedFR.Path, origFR.Path)
		}

		if loadedFR.RiskScore != origFR.RiskScore {
			t.Errorf("file %q: risk score = %d, want %d", key, loadedFR.RiskScore, origFR.RiskScore)
		}

		if loadedFR.RiskLevel != origFR.RiskLevel {
			t.Errorf("file %q: risk level = %q, want %q", key, loadedFR.RiskLevel, origFR.RiskLevel)
		}
	}
}
