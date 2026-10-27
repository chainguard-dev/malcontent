// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// orderedOf returns the reports keyed by keys, set in order, each with a
// risk score of its position.
func orderedOf(keys ...string) *OrderedFileReports {
	m := new(OrderedFileReports)
	for i, k := range keys {
		m.Set(k, &FileReport{Path: k, RiskScore: i})
	}
	return m
}

// entries returns the keys and risk scores of m, oldest first.
func entries(m *OrderedFileReports) []string {
	var got []string
	for e := m.Oldest(); e != nil; e = e.Next() {
		got = append(got, e.Key+"="+string(rune('0'+e.Value.RiskScore)))
	}
	return got
}

func TestOrderedFileReports(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		build   func() *OrderedFileReports
		want    []string
		wantLen int
	}{
		{
			name:  "zero value is empty",
			build: func() *OrderedFileReports { return new(OrderedFileReports) },
		},
		{
			name:  "nil map is empty",
			build: func() *OrderedFileReports { return nil },
		},
		{
			name:    "entries keep the order they were first set",
			build:   func() *OrderedFileReports { return orderedOf("/c", "/a", "/b") },
			want:    []string{"/c=0", "/a=1", "/b=2"},
			wantLen: 3,
		},
		{
			name: "setting a key again replaces its report in place",
			build: func() *OrderedFileReports {
				m := orderedOf("/a", "/b", "/c")
				m.Set("/a", &FileReport{Path: "/a", RiskScore: 9})
				return m
			},
			want:    []string{"/a=9", "/b=1", "/c=2"},
			wantLen: 3,
		},
		{
			name: "deleting the middle entry joins its neighbors",
			build: func() *OrderedFileReports {
				m := orderedOf("/a", "/b", "/c")
				m.Delete("/b")
				return m
			},
			want:    []string{"/a=0", "/c=2"},
			wantLen: 2,
		},
		{
			name: "deleting the ends and a missing key",
			build: func() *OrderedFileReports {
				m := orderedOf("/a", "/b", "/c")
				m.Delete("/a")
				m.Delete("/c")
				m.Delete("/missing")
				return m
			},
			want:    []string{"/b=1"},
			wantLen: 1,
		},
		{
			name: "a deleted key set again goes last",
			build: func() *OrderedFileReports {
				m := orderedOf("/a", "/b")
				m.Delete("/a")
				m.Set("/a", &FileReport{Path: "/a", RiskScore: 5})
				return m
			},
			want:    []string{"/b=1", "/a=5"},
			wantLen: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := tt.build()
			if got := entries(m); !slices.Equal(got, tt.want) {
				t.Errorf("entries: got = %q, want = %q", got, tt.want)
			}
			if got := m.Len(); got != tt.wantLen {
				t.Errorf("Len: got = %d, want = %d", got, tt.wantLen)
			}
		})
	}
}

func TestOrderedFileReportsGet(t *testing.T) {
	t.Parallel()
	m := orderedOf("/a", "/b")
	tests := []struct {
		name      string
		m         *OrderedFileReports
		key       string
		wantScore int
		wantOK    bool
	}{
		{name: "present key", m: m, key: "/b", wantScore: 1, wantOK: true},
		{name: "missing key", m: m, key: "/missing"},
		{name: "nil map", key: "/a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fr, ok := tt.m.Get(tt.key)
			if ok != tt.wantOK {
				t.Fatalf("Get(%q) ok: got = %v, want = %v", tt.key, ok, tt.wantOK)
			}
			if ok && fr.RiskScore != tt.wantScore {
				t.Errorf("Get(%q) risk: got = %d, want = %d", tt.key, fr.RiskScore, tt.wantScore)
			}
		})
	}
}

func TestOrderedFileReportsJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		m    *OrderedFileReports
		want string
	}{
		{name: "nil map is null", want: "null"},
		{name: "empty map is an empty object", m: new(OrderedFileReports), want: "{}"},
		{
			name: "keys keep their order and escape as encoding/json does",
			m:    orderedOf("/z", "<a>&\u2028"),
			want: `{"/z":{"Path":"/z","SHA256":"","Size":0,"RiskScore":0},"\u003ca\u003e\u0026\u2028":{"Path":"\u003ca\u003e\u0026\u2028","SHA256":"","Size":0,"RiskScore":1}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tt.m)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("Marshal: got = %s, want = %s", got, tt.want)
			}
		})
	}
}

func TestOrderedFileReportsUnmarshalJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    string
		want    []string
		wantErr string
	}{
		{name: "empty object", data: `{}`},
		{name: "entries keep the input order", data: `{"/c":{"RiskScore":0},"/a":{"RiskScore":1},"/b":{"RiskScore":2}}`, want: []string{"/c=0", "/a=1", "/b=2"}},
		{name: "a repeated key keeps its first place and last report", data: `{"/a":{"RiskScore":1},"/b":{"RiskScore":2},"/a":{"RiskScore":3}}`, want: []string{"/a=3", "/b=2"}},
		{name: "escaped keys decode", data: `{"\u003cx\u003e":{"RiskScore":4}}`, want: []string{"<x>=4"}},
		{name: "array is not a map", data: `[]`, wantErr: "want a JSON object"},
		{name: "string is not a map", data: `"x"`, wantErr: "want a JSON object"},
		{name: "report of the wrong type", data: `{"/a":7}`, wantErr: "cannot unmarshal number"},
		{name: "null leaves the map as it is", data: `null`},
		{name: "truncated object", data: `{"/a":{}`, wantErr: "unexpected end of JSON input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := new(OrderedFileReports)
			err := json.Unmarshal([]byte(tt.data), m)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Unmarshal(%s) error: got = %v, want one containing %q", tt.data, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal(%s): %v", tt.data, err)
			}
			if got := entries(m); !slices.Equal(got, tt.want) {
				t.Errorf("entries: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestDiffReportRoundTrips(t *testing.T) {
	t.Parallel()
	in := DiffReport{Added: orderedOf("/z", "/a"), Modified: orderedOf("/m", "/b", "/k")}
	codecs := []struct {
		name      string
		marshal   func(any) ([]byte, error)
		unmarshal func([]byte, any) error
	}{
		{"json", json.Marshal, json.Unmarshal},
		{"yaml", yaml.Marshal, yaml.Unmarshal},
	}
	for _, c := range codecs {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			data, err := c.marshal(in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var out DiffReport
			if err := c.unmarshal(data, &out); err != nil {
				t.Fatalf("unmarshal %s: %v", data, err)
			}
			if out.Removed != nil {
				t.Errorf("Removed: got = %q, want = nil, as an omitted field", entries(out.Removed))
			}
			if got, want := entries(out.Added), entries(in.Added); !slices.Equal(got, want) {
				t.Errorf("Added: got = %q, want = %q", got, want)
			}
			if got, want := entries(out.Modified), entries(in.Modified); !slices.Equal(got, want) {
				t.Errorf("Modified: got = %q, want = %q", got, want)
			}
		})
	}
}

func TestOrderedFileReportsYAML(t *testing.T) {
	t.Parallel()
	got, err := yaml.Marshal(orderedOf("/z", "/a"))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "/z:\n    path: /z\n    sha256: \"\"\n    size: 0\n    riskscore: 0\n/a:\n    path: /a\n    sha256: \"\"\n    size: 0\n    riskscore: 1\n"
	if string(got) != want {
		t.Errorf("Marshal: got = %q, want = %q", got, want)
	}
}

func TestOrderedFileReportsUnmarshalYAML(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    string
		want    []string
		wantErr string
	}{
		{name: "empty mapping", data: "{}"},
		{name: "entries keep the input order", data: "/c: {riskscore: 0}\n/a: {riskscore: 1}\n", want: []string{"/c=0", "/a=1"}},
		{name: "sequence is not a map", data: "- a\n", wantErr: "want a YAML mapping"},
		{name: "scalar is not a map", data: "x\n", wantErr: "want a YAML mapping"},
		{name: "report of the wrong type", data: "/a: [1]\n", wantErr: "cannot unmarshal"},
		{name: "non-scalar key", data: "? [a]\n: {}\n", wantErr: "cannot unmarshal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := new(OrderedFileReports)
			err := yaml.Unmarshal([]byte(tt.data), m)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Unmarshal(%q) error: got = %v, want one containing %q", tt.data, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal(%q): %v", tt.data, err)
			}
			if got := entries(m); !slices.Equal(got, tt.want) {
				t.Errorf("entries: got = %q, want = %q", got, tt.want)
			}
		})
	}
}
