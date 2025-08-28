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
		{"snmpd", &FileType{MIME: "text/x-shellscript", Ext: "sh"}},
		{"test.pl", &FileType{MIME: "text/x-perl", Ext: "pl"}},
		{"peclcmd", &FileType{MIME: "text/x-php", Ext: "php"}},
		{"test.sh", &FileType{MIME: "text/x-shellscript", Ext: "sh"}},
		{"libpam.so.0", &FileType{MIME: "application/x-sharedlib", Ext: "so"}},
		{"ls", &FileType{MIME: "application/x-elf", Ext: "elf"}},
		{"tiny", &FileType{MIME: "application/x-elf", Ext: "elf"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := File(filepath.Join("testdata/", tt.in))
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
