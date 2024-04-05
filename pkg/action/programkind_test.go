// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"fmt"
	"testing"
)

func TestProgramKindMagic(t *testing.T) {

}

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
			got := programKind(fmt.Sprintf("testdata/%s", tt.filename))
			if got != tt.want {
				t.Errorf("programKind() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProgramKindExtensions(t *testing.T) {
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
		want:     "",
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
			exists, kind := byExtension(tt.filename)
			if exists != !tt.notFound {
				t.Errorf("byExtension() exists = %v, want %v", exists, !tt.notFound)
			}
			if kind != tt.want {
				t.Errorf("byExtension() kind = %v, want %v", kind, tt.want)
			}
		})
	}
}
