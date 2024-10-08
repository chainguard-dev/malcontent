// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"fmt"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
)

func TestProgramStringMatch(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{{
		filename: "python",
		want:     "Python script",
	}, {
		filename: "shell",
		want:     "Shell script",
	}, {
		filename: "short",
		want:     "",
	}, {
		filename: "empty",
		want:     "",
	}, {
		filename: "rando", // generated with : `head -c 1024 </dev/urandom >pkg/action/testdata/rando`
	}, {
		filename: "juttu",
		want:     "",
	}}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			ctx := slogtest.Context(t)
			got, err := File(ctx, fmt.Sprintf("testdata/%s", tt.filename))
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got.MIME != tt.want {
				t.Errorf("programKind() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestByPath(t *testing.T) {
	tests := []struct {
		filename string
		want     string
		notFound bool // true if the file extension is not found in the map
	}{{
		filename: "applescript.scpt",
		want:     "compiled AppleScript",
	}, {
		filename: "applescript.scptd",
		want:     "compiled AppleScript",
	}, {
		filename: "shell.sh",
		want:     "Shell script",
	}, {
		filename: "ruby.rb",
		want:     "Ruby script",
	}, {
		filename: "python.py",
		want:     "Python script",
	}, {
		filename: "perl.pl",
		want:     "PERL script",
	}, {
		filename: "yara.yara",
		want:     "",
	}, {
		filename: "expect.expect",
		want:     "Expect script",
	}, {
		filename: "php.php",
		want:     "PHP file",
	}, {
		filename: "html.html",
		want:     "",
	}, {
		filename: "javascript.js",
		want:     "Javascript",
	}, {
		filename: "typescript.ts",
		want:     "Typescript",
	}, {
		filename: "7z.7z",
		want:     "",
	}, {
		filename: "json.json",
		want:     "Javascript",
	}, {
		filename: "yaml.yml",
		want:     "",
	}, {
		filename: "yaml.yaml",
		want:     "",
	}, {
		filename: "java.java",
		want:     "Java source",
	}, {
		filename: "java.jar",
		want:     "Java program",
	}, {
		filename: "asm.asm",
		want:     "",
	}, {
		filename: "systemd.service",
		want:     "systemd",
	}, {
		filename: "crontab.cron",
		want:     "crontab",
	}, {
		filename: "crontab.crontab",
		want:     "crontab",
	}, {
		filename: "c.c",
		want:     "C source",
	}, {
		filename: "juttu.juttu",
		notFound: true,
	}}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			kind, err := Path(tt.filename)
			if exists != !tt.notFound {
				t.Errorf("byExtension(%s) exists = %v, want %v", tt.filename, exists, !tt.notFound)
			}
			if kind != tt.want {
				t.Errorf("byExtension(%s) kind = %v, want %v", tt.filename, kind, tt.want)
			}
		})
	}
}

func TestGetExt(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{
			path: "testdata/file.apk",
			want: ".apk",
		}, {
			path: "testdata/file.jar",
			want: ".jar",
		}, {
			path: "testdata/file.tar",
			want: ".tar",
		}, {
			path: "testdata/file.tgz",
			want: ".tgz",
		}, {
			path: "testdata/file.tar.gz",
			want: ".tar.gz",
		}, {
			path: "testdata/file.tar.xz",
			want: ".tar.xz",
		}, {
			path: "testdata/file.zip",
			want: ".zip",
		}, {
			path: "testdata/file_1.0.0",
			want: "",
		}, {
			path: "testdata/file_1.0.0.apk",
			want: ".apk",
		}, {
			path: "testdata/file_1.0.0.jar",
			want: ".jar",
		}, {
			path: "testdata/file_1.0.0.tar",
			want: ".tar",
		}, {
			path: "testdata/file_1.0.0.tgz",
			want: ".tgz",
		}, {
			path: "testdata/file_1.0.0.tar.gz",
			want: ".tar.gz",
		}, {
			path: "testdata/file_1.0.0.tar.xz",
			want: ".tar.xz",
		}, {
			path: "testdata/file_1.0.0.zip",
			want: ".zip",
		}, {
			path: "testdata/file.a.b.c.tar.gz",
			want: ".tar.gz",
		}, {
			path: "testdata/file_a.b.c.tar.xz",
			want: ".tar.xz",
		}, {
			path: "testdata/file_a.b.0.tar",
			want: ".tar",
		}, {
			path: "testdata/file_no_ext",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := Ext(tt.path); got != tt.want {
				t.Errorf("Ext() = %v, want %v", got, tt.want)
			}
		})
	}
}
