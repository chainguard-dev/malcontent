// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package yrx

import (
	"bytes"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
)

const testRule = `rule needle { strings: $a = "needle" condition: $a }`

// matches returns the identifiers of the rules in r that match data.
func matches(t *testing.T, r *yarax.Rules, data string) []string {
	t.Helper()
	s := yarax.NewScanner(r)
	defer s.Destroy()
	res, err := s.Scan([]byte(data))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	matched := res.MatchingRules()
	got := make([]string, 0, len(matched))
	for _, m := range matched {
		got = append(got, m.Identifier())
	}
	return got
}

func TestCompileReadFromDestroy(t *testing.T) {
	t.Parallel()
	compiled, err := Compile(testRule)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	defer Destroy(compiled)
	if got := matches(t, compiled, "a needle"); len(got) != 1 || got[0] != "needle" {
		t.Errorf("compiled rules matches: got = %q, want = [needle]", got)
	}

	var buf bytes.Buffer
	if _, err := compiled.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	loaded, err := ReadFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	defer Destroy(loaded)
	if got := matches(t, loaded, "a needle"); len(got) != 1 || got[0] != "needle" {
		t.Errorf("loaded rules matches: got = %q, want = [needle]", got)
	}
	if got := matches(t, loaded, "nothing here"); len(got) != 0 {
		t.Errorf("loaded rules matches without the needle: got = %q, want none", got)
	}
	Destroy(nil)
}

func TestCompileReportsBadSource(t *testing.T) {
	t.Parallel()
	if r, err := Compile("rule broken {"); err == nil {
		Destroy(r)
		t.Error("Compile: got = nil error, want a syntax error")
	}
}

// swap sets *p to v until the test ends.
func swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// TestCallsRunInsideTheLock records the order in which each function takes
// the lock, calls YARA-X, and releases the lock. It must not call t.Parallel,
// since it replaces package variables.
func TestCallsRunInsideTheLock(t *testing.T) {
	var got []string
	record := func(event string) { got = append(got, event) }
	swap(t, &lock, func() { record("lock") })
	swap(t, &unlock, func() { record("unlock") })
	swap(t, &build, func(*yarax.Compiler) *yarax.Rules { record("build"); return &yarax.Rules{} })
	swap(t, &readFrom, func(io.Reader) (*yarax.Rules, error) { record("readFrom"); return &yarax.Rules{}, nil })
	swap(t, &destroy, func(*yarax.Rules) { record("destroy") })

	compiler := func() *yarax.Compiler {
		c, err := yarax.NewCompiler()
		if err != nil {
			t.Fatalf("NewCompiler: %v", err)
		}
		t.Cleanup(c.Destroy)
		if err := c.AddSource(testRule); err != nil {
			t.Fatalf("AddSource: %v", err)
		}
		return c
	}
	tests := []struct {
		name string
		call func()
		want []string
	}{
		{name: "Build", call: func() { runtime.SetFinalizer(Build(compiler()), nil) }, want: []string{"lock", "build", "unlock"}},
		{name: "Compile", call: func() {
			r, err := Compile(testRule)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			runtime.SetFinalizer(r, nil)
		}, want: []string{"lock", "build", "unlock"}},
		{name: "ReadFrom", call: func() { _, _ = ReadFrom(strings.NewReader("")) }, want: []string{"lock", "readFrom", "unlock"}},
		{name: "Destroy", call: func() { Destroy(&yarax.Rules{}) }, want: []string{"lock", "destroy", "unlock"}},
		{name: "Destroy of nil takes nothing", call: func() { Destroy(nil) }, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got = nil
			tt.call()
			if !slices.Equal(got, tt.want) {
				t.Errorf("calls: got = %q, want = %q", got, tt.want)
			}
		})
	}
}
