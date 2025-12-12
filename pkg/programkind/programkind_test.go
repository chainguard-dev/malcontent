// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFile(t *testing.T) {
	tests := []struct {
		in   string
		want *FileType
	}{
		{"expr", &FileType{MIME: "application/x-mach-binary", Ext: "macho"}},
		{"ls", &FileType{MIME: "application/x-elf", Ext: "elf"}},
		{"tiny", &FileType{MIME: "application/x-elf", Ext: "elf"}},
		{"libpam.so.0", &FileType{MIME: "application/x-sharedlib", Ext: "so"}},
		{"test.sh", &FileType{MIME: "text/x-shellscript", Ext: "sh"}},
		{"snmpd", &FileType{MIME: "text/x-shellscript", Ext: "sh"}},
		{"shell_no_ext", &FileType{MIME: "text/x-shellscript", Ext: "sh"}},
		{"shell_patterns", &FileType{MIME: "text/x-shellscript", Ext: "sh"}},
		{"test.pl", &FileType{MIME: "text/x-perl", Ext: "pl"}},
		{"peclcmd", &FileType{MIME: "text/x-php", Ext: "php"}},
		{"test.vbs", &FileType{MIME: "text/x-vbscript", Ext: "vbs"}},
		{"app-1.2.3", &FileType{MIME: "text/x-php", Ext: "php"}},
		{"readme.md", nil},
		{"config.yaml", nil},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := File(t.Context(), filepath.Join("testdata/", tt.in))
			if err != nil {
				t.Errorf("File(%s) returned error: %v", tt.in, err)
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("File(%s) = %v, want %v, diff: %s", tt.in, got, tt.want, diff)
			}
		})
	}
}

func TestPath(t *testing.T) {
	tests := []struct {
		in   string
		want *FileType
	}{
		{"applescript.scpt", &FileType{MIME: "application/x-applescript", Ext: "scpt"}},
		{"./shell.sh", &FileType{MIME: "text/x-shellscript", Ext: "sh"}},
		{"ls", nil},
		{"/etc/systemd/system/launcher.service", &FileType{MIME: "text/x-systemd", Ext: "service"}},
		{"yarn-package.json", &FileType{MIME: "application/json", Ext: "json"}},
		{"/home/yeti/.hidden/package.json", &FileType{MIME: "application/json", Ext: "json"}},
		{"unknown.json", nil},
		{"script.vbs", &FileType{MIME: "text/x-vbscript", Ext: "vbs"}},
		{"composer-2.7.7", nil},
		{"file.tar.gz", &FileType{MIME: "", Ext: "tar.gz"}},
		{"archive.gz", &FileType{MIME: "", Ext: "gz"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := Path(tt.in)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Path(%s) = %v, want %v, diff: %s", tt.in, got, tt.want, diff)
			}
		})
	}
}

func TestGetExt(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantGetExt  string
		wantPathExt string
		note        string
	}{
		{
			name:        "simple shell script",
			path:        "script.sh",
			wantGetExt:  ".sh",
			wantPathExt: ".sh",
		},
		{
			name:        "simple python",
			path:        "app.py",
			wantGetExt:  ".py",
			wantPathExt: ".py",
		},
		{
			name:        "simple javascript",
			path:        "index.js",
			wantGetExt:  ".js",
			wantPathExt: ".js",
		},
		{
			name:        "no extension",
			path:        "binary",
			wantGetExt:  "",
			wantPathExt: "",
		},
		{
			name:        "hidden file no extension",
			path:        ".bashrc",
			wantGetExt:  ".bashrc",
			wantPathExt: ".bashrc",
		},

		{
			name:        "tar.gz archive",
			path:        "file.tar.gz",
			wantGetExt:  ".tar.gz",
			wantPathExt: ".gz",
			note:        "GetExt recognizes .tar.gz as a single archive extension",
		},
		{
			name:        "tar.xz archive",
			path:        "backup.tar.xz",
			wantGetExt:  ".tar.xz",
			wantPathExt: ".xz",
			note:        "GetExt recognizes .tar.xz as a single archive extension",
		},
		{
			name:        "simple gz (not tar)",
			path:        "data.gz",
			wantGetExt:  ".gz",
			wantPathExt: ".gz",
		},

		{
			name:        "version number suffix",
			path:        "composer-2.7.7",
			wantGetExt:  "",
			wantPathExt: ".7",
			note:        "GetExt strips version numbers like X.Y.Z from the end",
		},
		{
			name:        "version with extension",
			path:        "app-1.2.3.tar.gz",
			wantGetExt:  ".tar.gz",
			wantPathExt: ".gz",
			note:        "GetExt strips version and returns multi-part archive extension",
		},
		{
			name:        "library with version",
			path:        "libfoo-2.0.1.so",
			wantGetExt:  ".so",
			wantPathExt: ".so",
			note:        "GetExt strips version but .so is still the final extension",
		},
		{
			name:        "shared library versioned",
			path:        "libpam.so.0",
			wantGetExt:  ".0",
			wantPathExt: ".0",
			note:        ".so.0 is not in ArchiveMap so returns last part",
		},
		{
			name:        "shared library multi-version",
			path:        "libssl.so.1.1",
			wantGetExt:  ".1",
			wantPathExt: ".1",
		},
		{
			name:        "multiple dots not archive",
			path:        "file.backup.old",
			wantGetExt:  ".old",
			wantPathExt: ".old",
			note:        ".backup.old is not in ArchiveMap so returns last part",
		},
		{
			name:        "path with directories",
			path:        "/home/user/project/file.tar.gz",
			wantGetExt:  ".tar.gz",
			wantPathExt: ".gz",
		},
		{
			name:        "dotfile with extension",
			path:        ".config.yaml",
			wantGetExt:  ".yaml",
			wantPathExt: ".yaml",
		},
		{
			name:        "package.json special case",
			path:        "package.json",
			wantGetExt:  ".json",
			wantPathExt: ".json",
		},
		{
			name:        "js.map file",
			path:        "bundle.js.map",
			wantGetExt:  ".map",
			wantPathExt: ".map",
			note:        ".js.map is not in ArchiveMap so returns last part",
		},
		{
			name:        "elf extension",
			path:        "program.elf",
			wantGetExt:  ".elf",
			wantPathExt: ".elf",
		},
		{
			name:        "macho extension",
			path:        "binary.macho",
			wantGetExt:  ".macho",
			wantPathExt: ".macho",
		},
		{
			name:        "vbscript",
			path:        "script.vbs",
			wantGetExt:  ".vbs",
			wantPathExt: ".vbs",
		},
		{
			name:        "applescript",
			path:        "automation.scpt",
			wantGetExt:  ".scpt",
			wantPathExt: ".scpt",
		},
		{
			name:        "systemd service",
			path:        "app.service",
			wantGetExt:  ".service",
			wantPathExt: ".service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotGetExt := GetExt(tt.path)
			gotPathExt := filepath.Ext(tt.path)

			if gotGetExt != tt.wantGetExt {
				t.Errorf("GetExt(%q) = %q, want %q", tt.path, gotGetExt, tt.wantGetExt)
			}

			if gotPathExt != tt.wantPathExt {
				t.Errorf("filepath.Ext(%q) = %q, want %q (this documents expected stdlib behavior)",
					tt.path, gotPathExt, tt.wantPathExt)
			}

			if gotGetExt != gotPathExt && tt.note == "" {
				t.Logf("Note: GetExt and filepath.Ext differ for %q: GetExt=%q, filepath.Ext=%q",
					tt.path, gotGetExt, gotPathExt)
			}
		})
	}
}

func TestGetExtArchiveMapCoverage(t *testing.T) {
	for ext := range ArchiveMap {
		t.Run(ext, func(t *testing.T) {
			filename := "testfile" + ext
			got := GetExt(filename)

			if got != ext {
				stdExt := filepath.Ext(filename)
				if got == stdExt {
					return
				}
				t.Errorf("GetExt(%q) = %q, want %q", filename, got, ext)
			}
		})
	}
}

func TestGetExtSupportedKindCoverage(t *testing.T) {
	for ext := range supportedKind {
		t.Run(ext, func(t *testing.T) {
			filename := "testfile." + ext
			got := GetExt(filename)
			want := "." + ext

			if got != want {
				t.Errorf("GetExt(%q) = %q, want %q", filename, got, want)
			}

			stdExt := filepath.Ext(filename)
			if stdExt != want {
				t.Errorf("filepath.Ext(%q) = %q, want %q (unexpected stdlib behavior)", filename, stdExt, want)
			}
		})
	}
}

func TestIsLikelyShellScript(t *testing.T) {
	tests := []struct {
		name    string
		content string
		path    string
		want    bool
	}{
		{
			name:    "bash shebang",
			content: "#!/bin/bash\necho hello",
			path:    "script",
			want:    true,
		},
		{
			name:    "sh shebang",
			content: "#!/bin/sh\ntest",
			path:    "script",
			want:    true,
		},
		{
			name:    "env bash shebang",
			content: "#!/usr/bin/env bash\necho hello",
			path:    "script",
			want:    true,
		},
		{
			name:    "profile suffix",
			content: "export PATH=/bin",
			path:    "/etc/profile",
			want:    true,
		},
		{
			name:    "bashrc",
			content: "alias ls='ls -la'",
			path:    "/home/user/.bashrc",
			want:    true,
		},
		{
			name:    "zshrc",
			content: "export ZSH=$HOME/.oh-my-zsh",
			path:    "/home/user/.zshrc",
			want:    true,
		},
		{
			name:    "multiple shell patterns",
			content: "set -e\nexport PATH=/bin\nif [ -f test ]; then\necho test\nfi\n",
			path:    "script",
			want:    true,
		},
		{
			name:    "command substitution and parameter expansion",
			content: "VAR=$(cat file)\necho ${VAR}\n",
			path:    "script",
			want:    true,
		},
		{
			name:    "single echo - not enough",
			content: "echo hello world",
			path:    "file",
			want:    false,
		},
		{
			name:    "markdown with shell examples",
			content: "# README\nUse `echo hello` to print\nRun `grep pattern`",
			path:    "README.md",
			want:    false,
		},
		{
			name:    "documentation mentioning commands",
			content: "The grep command searches files.\nUse echo to print output.",
			path:    "docs.txt",
			want:    false,
		},
		{
			name:    "empty file",
			content: "",
			path:    "empty",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyShellScript([]byte(tt.content), tt.path)
			if got != tt.want {
				t.Errorf("isLikelyShellScript(%q, %q) = %v, want %v", tt.content, tt.path, got, tt.want)
			}
		})
	}
}
