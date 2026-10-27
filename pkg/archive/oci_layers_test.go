// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"fmt"
	"testing"

	"github.com/chainguard-dev/clog"
)

// TestOCIWithConfig_LayersMatchContainerd checks that the extracted image is
// the filesystem containerd runs: whiteouts hide only lower layers, hardlinks
// keep their bytes when an upper layer hides or replaces their target (overlay
// copy-up), entries resolve through lower-layer symlinks, and names are rooted
// as containerd roots them. Content an upper layer deletes is not extracted,
// and an entry that cannot be applied is skipped with a warning rather than
// failing the image.
func TestOCIWithConfig_LayersMatchContainerd(t *testing.T) {
	t.Parallel()
	type layers = [][]ociTestEntry
	cases := []struct {
		name     string
		layers   layers
		want     map[string]string
		wantWarn int // skipped-entry warnings
	}{
		{
			name:   "a whiteout before a file in the same layer keeps the file",
			layers: layers{{{name: "evil", body: "old"}}, {{name: ".wh.evil"}, {name: "evil", body: "new"}}},
			want:   map[string]string{"evil": "file:new"},
		},
		{
			name: "a directory whiteout before entries in the same layer keeps those entries",
			layers: layers{
				{{name: "app/old", body: "o"}},
				{{name: ".wh.app"}, {name: "app/run", body: "r"}},
			},
			want: map[string]string{"app": "dir", "app/run": "file:r"},
		},
		{
			name:   "a whiteout after a file in the same layer keeps the file",
			layers: layers{{{name: "evil", body: "old"}}, {{name: "evil", body: "new"}, {name: ".wh.evil"}}},
			want:   map[string]string{"evil": "file:new"},
		},
		{
			name:   "a whiteout hides the lower layer's file",
			layers: layers{{{name: "evil", body: "old"}, {name: "keep", body: "k"}}, {{name: ".wh.evil"}}},
			want:   map[string]string{"keep": "file:k"},
		},
		{
			name:   "a directory whiteout hides the lower layer's tree",
			layers: layers{{{name: "app/a", body: "a"}, {name: "app/b/c", body: "c"}, {name: "keep", body: "k"}}, {{name: ".wh.app"}}},
			want:   map[string]string{"keep": "file:k"},
		},
		{
			name: "an opaque directory hides lower entries and keeps its own",
			layers: layers{
				{{name: "d/old", body: "o"}},
				{ociDirEntry("d/"), {name: "d/.wh..wh..opq"}, {name: "d/new", body: "n"}},
			},
			want: map[string]string{"d": "dir", "d/new": "file:n"},
		},
		{
			name: "an opaque marker after same-layer entries keeps them",
			layers: layers{
				{{name: "d/old", body: "o"}, {name: "d/sub/old", body: "o"}},
				{{name: "d/new", body: "n"}, {name: "d/sub/new", body: "s"}, {name: "d/.wh..wh..opq"}},
			},
			want: map[string]string{"d": "dir", "d/new": "file:n", "d/sub": "dir", "d/sub/new": "file:s"},
		},
		{
			name: "a hardlink keeps its bytes when an upper layer whites out the target",
			layers: layers{
				{{name: "usr/bin/evil", body: "payload"}, ociHardlinkEntry("usr/bin/run", "usr/bin/evil")},
				{{name: "usr/bin/.wh.evil"}},
			},
			want: map[string]string{"usr": "dir", "usr/bin": "dir", "usr/bin/run": "file:payload"},
		},
		{
			name: "a hardlink keeps its bytes when an upper layer replaces the target",
			layers: layers{
				{{name: "x", body: "payload"}, ociHardlinkEntry("run", "x")},
				{{name: "x", body: "benign"}},
			},
			want: map[string]string{"x": "file:benign", "run": "file:payload"},
		},
		{
			name: "a hardlink to a symlink is a second symlink",
			layers: layers{{
				{name: "bin/busybox", body: "b"},
				ociLinkEntry("bin/sh", "busybox"),
				ociHardlinkEntry("bin/ash", "bin/sh"),
			}},
			want: map[string]string{"bin": "dir", "bin/busybox": "file:b", "bin/sh": "link:busybox", "bin/ash": "link:busybox"},
		},
		{
			name: "an upper entry under a lower symlink lands in the symlink's target",
			layers: layers{
				{ociDirEntry("usr/lib/"), ociLinkEntry("lib", "usr/lib")},
				{{name: "lib/x", body: "payload"}},
			},
			want: map[string]string{"usr": "dir", "usr/lib": "dir", "usr/lib/x": "file:payload", "lib": "link:usr/lib"},
		},
		{
			name: "an absolute symlink in a parent resolves inside the root",
			layers: layers{
				{ociDirEntry("etc/"), ociLinkEntry("conf", "/etc")},
				{{name: "conf/app.cfg", body: "c"}},
			},
			want: map[string]string{"etc": "dir", "etc/app.cfg": "file:c", "conf": "link:etc"},
		},
		{
			name: "a symlink that climbs out of the root is clamped to it",
			layers: layers{
				{ociLinkEntry("esc", "../../../outside")},
				{{name: "esc/x", body: "payload"}},
			},
			want: map[string]string{"outside": "dir", "outside/x": "file:payload", "esc": "link:outside"},
		},
		{
			name: "a nested absolute symlink becomes relative to its directory",
			layers: layers{{
				{name: "bin/busybox", body: "b"},
				ociLinkEntry("usr/bin/sh", "/bin/busybox"),
			}},
			want: map[string]string{"bin": "dir", "bin/busybox": "file:b", "usr": "dir", "usr/bin": "dir", "usr/bin/sh": "link:../../bin/busybox"},
		},
		{
			name:   "absolute entry names are rooted as ko writes them",
			layers: layers{{ociDirEntry("ko-app"), {name: "/ko-app/hello", body: "h"}, {name: "/var/run/ko/data", body: "d"}}},
			want: map[string]string{
				"ko-app": "dir", "ko-app/hello": "file:h",
				"var": "dir", "var/run": "dir", "var/run/ko": "dir", "var/run/ko/data": "file:d",
			},
		},
		{
			name:   "dot-dot entry names stop at the root",
			layers: layers{{{name: "../../x", body: "payload"}, {name: "a/../../y", body: "y"}}},
			want:   map[string]string{"x": "file:payload", "y": "file:y"},
		},
		{
			name:   "drive letters, backslashes, and dots are plain name characters",
			layers: layers{{{name: "c:payload", body: "a"}, {name: `a\..\..\b`, body: "b"}, {name: "x../y", body: "c"}}},
			want:   map[string]string{"c:payload": "file:a", `a\..\..\b`: "file:b", "x..": "dir", "x../y": "file:c"},
		},
		{
			name:   "a file replaces a lower directory",
			layers: layers{{{name: "bin/sh", body: "s"}}, {{name: "bin", body: "f"}}},
			want:   map[string]string{"bin": "file:f"},
		},
		{
			name:   "a directory replaces a lower file",
			layers: layers{{{name: "x", body: "f"}}, {ociDirEntry("x/"), {name: "x/y", body: "y"}}},
			want:   map[string]string{"x": "dir", "x/y": "file:y"},
		},
		{
			name:   "a later duplicate in the same layer wins",
			layers: layers{{{name: "x", body: "one"}, {name: "x", body: "two"}}},
			want:   map[string]string{"x": "file:two"},
		},
		{
			name:     "a hardlink to a missing target is skipped and logged",
			layers:   layers{{{name: "ok", body: "k"}, ociHardlinkEntry("run", "gone")}},
			want:     map[string]string{"ok": "file:k"},
			wantWarn: 1,
		},
		{
			name:     "a hardlink to a directory is skipped and logged",
			layers:   layers{{ociDirEntry("d/"), ociHardlinkEntry("run", "d")}},
			want:     map[string]string{"d": "dir"},
			wantWarn: 1,
		},
		{
			name:     "an entry below a regular file is skipped and logged",
			layers:   layers{{{name: "f", body: "f"}, {name: "f/x", body: "x"}}},
			want:     map[string]string{"f": "file:f"},
			wantWarn: 1,
		},
		{
			name:     "a symlink loop is skipped and logged",
			layers:   layers{{ociLinkEntry("a", "b"), ociLinkEntry("b", "a"), {name: "a/x", body: "x"}, {name: "ok", body: "k"}}},
			want:     map[string]string{"ok": "file:k"},
			wantWarn: 3,
		},
		{
			name:     "a whiteout naming its own directory is skipped and logged",
			layers:   layers{{{name: "d/f", body: "f"}}, {{name: "d/.wh.."}}},
			want:     map[string]string{"d": "dir", "d/f": "file:f"},
			wantWarn: 1,
		},
		{
			name:     "a device node replaces the lower entry and is logged",
			layers:   layers{{{name: "dev/null", body: "lower"}}, {{name: "dev/null", typeflag: tar.TypeChar}}},
			want:     map[string]string{"dev": "dir"},
			wantWarn: 1,
		},
	}
	host := ociTestRegistry(t)
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ref := fmt.Sprintf("%s/layers:case%d", host, i)
			ociPushImage(t, ref, ociTestImage(t, tc.layers...))
			rec := &ociWarnRecorder{}
			ctx := clog.WithLogger(t.Context(), clog.New(rec))
			dir, err := OCIWithConfig(ctx, ref, ociTestConfig(0))
			removeOCIDir(t, dir)
			if err != nil {
				t.Fatalf("OCIWithConfig: %v", err)
			}
			ociAssertTree(t, dir, tc.want)
			if got := rec.count(ociSkipWarning); got != tc.wantWarn {
				t.Errorf("skipped-entry warnings: got = %d, want = %d (%q)", got, tc.wantWarn, rec.msgs)
			}
		})
	}
}
