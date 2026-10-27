// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"strings"
	"testing"
)

func TestEntryName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		in          string
		want        string
		wantChanged bool
	}{
		{name: "relative name is kept", in: "usr/bin/tool", want: "usr/bin/tool"},
		{name: "leading dot slash is dropped quietly", in: "./usr/bin/tool", want: "usr/bin/tool"},
		{name: "trailing slash is dropped quietly", in: "lib/", want: "lib"},
		{name: "element ending in dots is kept", in: "v1../notes.txt", want: "v1../notes.txt"},
		{name: "dots inside a name are kept", in: "lib/a..b.sh", want: "lib/a..b.sh"},
		{name: "climb that stays beneath the root is resolved quietly", in: "a/../b", want: "b"},
		{name: "leading climb is dropped", in: "../escape.txt", want: "escape.txt", wantChanged: true},
		{name: "climb past the root is dropped", in: "a/../../b.sh", want: "b.sh", wantChanged: true},
		{name: "absolute name is made relative", in: "/etc/passwd", want: "etc/passwd", wantChanged: true},
		{name: "doubled leading slash is made relative", in: "//double.php", want: "double.php", wantChanged: true},
		{name: "name is cut at a NUL byte", in: "run.py\x00.txt", want: "run.py", wantChanged: true},
		{name: "backslashes are part of the name", in: `..\win.bat`, want: `..\win.bat`},
		{name: "empty name is the root", in: "", want: "."},
		{name: "lone climb is the root", in: "..", want: ".", wantChanged: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, changed := entryName(tt.in)
			if got != tt.want || changed != tt.wantChanged {
				t.Errorf("entryName(%q): got = (%q, %v), want = (%q, %v)", tt.in, got, changed, tt.want, tt.wantChanged)
			}
		})
	}
}

func TestEntryNameShortensOverlongElements(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 300)
	tests := []struct {
		name    string
		in      string
		wantDir string
		wantExt string
	}{
		{name: "overlong file name keeps its extension", in: "dir/" + long + ".txt", wantDir: "dir", wantExt: ".txt"},
		{name: "overlong directory name is shortened too", in: long + "/f", wantDir: "", wantExt: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, changed := entryName(tt.in)
			if !changed {
				t.Errorf("entryName(%q): got changed = false, want = true", tt.in)
			}
			for elem := range strings.SplitSeq(got, "/") {
				if len(elem) > maxElementBytes {
					t.Errorf("entryName(%q): element of %d bytes, want at most %d", tt.in, len(elem), maxElementBytes)
				}
			}
			if !strings.HasSuffix(got, tt.wantExt) || tt.wantDir != "" && !strings.HasPrefix(got, tt.wantDir+"/") {
				t.Errorf("entryName(%q): got = %q, want it in %q ending in %q", tt.in, got, tt.wantDir, tt.wantExt)
			}
			if again, _ := entryName(tt.in); again != got {
				t.Errorf("entryName(%q): got %q then %q, want the same name", tt.in, got, again)
			}
		})
	}
	if a, _ := entryName(long + "x.txt"); a == func() string { b, _ := entryName(long + "y.txt"); return b }() {
		t.Errorf("distinct overlong names: got the same shortened name %q", a)
	}
}

func TestHandleSymlinkQuotesUntrustedText(t *testing.T) {
	t.Parallel()
	root := openTestRoot(t, t.TempDir())
	err := handleSymlink(root, "lnk\nforged entry", "../../outside\nforged target")
	if err == nil {
		t.Fatal("handleSymlink: got = nil, want an error for a link leaving the root")
	}
	if msg := err.Error(); strings.Contains(msg, "\n") || !strings.Contains(msg, `"lnk\nforged entry"`) {
		t.Errorf("handleSymlink error: got = %q, want names quoted with %%q", msg)
	}
}

func TestFileEntryNameNeverNamesTheRoot(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "/", ".", "..", "a/.."} {
		got, changed := fileEntryName(in)
		if got != unnamedEntry || !changed {
			t.Errorf("fileEntryName(%q): got = (%q, %v), want = (%q, true)", in, got, changed, unnamedEntry)
		}
	}
	if got, _ := fileEntryName("x/" + strings.Repeat("y", 3)); got != "x/yyy" {
		t.Errorf("fileEntryName: got = %q, want = %q", got, "x/yyy")
	}
}
