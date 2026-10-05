// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestExtractSkipsUnusableEntries(t *testing.T) {
	t.Parallel()
	// Map iteration order changes from call to call, so repeated calls reach
	// the nil and empty-path entries both before and after the usable one.
	const calls = 64
	tests := []struct {
		name    string
		extract func(map[string]*malcontent.FileReport) string
		path    string
		want    string
	}{
		{"image URI", ExtractImageURI, "cgr.dev/chainguard/nginx:latest ∴ /usr/bin/nginx", "cgr.dev/chainguard/nginx:latest"},
		{"temporary root", ExtractTmpRoot, "/tmp/abc/def/T/extract/bin/ls", "/tmp/abc/def/T/extract"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			files := map[string]*malcontent.FileReport{
				"nil":    nil,
				"empty":  {Path: ""},
				"plain":  {Path: "/usr/bin/plain"},
				"usable": {Path: tt.path},
			}
			for i := range calls {
				if got := tt.extract(files); got != tt.want {
					t.Fatalf("call %d: got = %q, want = %q", i, got, tt.want)
				}
			}
		})
	}
}

func TestExtractImageURISeparator(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want string
	}{
		{"image and path joined by the separator", "cgr.dev/chainguard/nginx:latest ∴ /usr/bin/nginx", "cgr.dev/chainguard/nginx:latest"},
		{"relative path without the separator is not an image", "bin/ls", ""},
		{"file name containing the symbol without spaces is not an image", "notes∴draft.txt", ""},
		{"symbol with a space on one side only is not a separator", "img ∴/usr/bin/nginx", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			files := map[string]*malcontent.FileReport{"key": {Path: tt.path}}
			if got := ExtractImageURI(files); got != tt.want {
				t.Errorf("ExtractImageURI(%q): got = %q, want = %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestReportPathCustomTmpRoot(t *testing.T) {
	t.Parallel()
	// A root outside the macOS and /tmp layouts that tempDirPattern knows, so
	// only the explicit tmpRoot argument can remove it.
	const root = "/scratch/extract"
	tests := []struct {
		name  string
		clean func(path, tmpRoot, imageURI string) string
		path  string
		want  string
	}{
		{"CleanReportPath removes the root", CleanReportPath, root + "/bin/ls", "/bin/ls"},
		{"CleanReportPath keeps the root when it is not a prefix", CleanReportPath, "/data" + root + "/bin/ls", "/data" + root + "/bin/ls"},
		{"FormatReportKey removes the root", FormatReportKey, root + "/bin/ls", "/bin/ls"},
		{"FormatReportKey keeps the root when it is not a prefix", FormatReportKey, "/data" + root + "/bin/ls", "/data" + root + "/bin/ls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.clean(tt.path, root, ""); got != tt.want {
				t.Errorf("got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestValidateIgnoreRulesChecksPatternsAfterBlanks(t *testing.T) {
	t.Parallel()
	err := ValidateIgnoreRules([]string{"  ", "", "py_lib_[abc"})
	if !errors.Is(err, filepath.ErrBadPattern) {
		t.Errorf("ValidateIgnoreRules: got = %v, want an error wrapping %v", err, filepath.ErrBadPattern)
	}
}
