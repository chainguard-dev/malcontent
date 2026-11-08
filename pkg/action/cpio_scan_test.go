// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/klauspost/compress/zstd"
)

// reverseShellParts are benign files of an initramfs that, read together,
// hold every string rule perl_reverse_shell needs: "socket(" and "open(",
// a redirection, and "sh -i". No one of them holds them all. The emergency
// shell function, like the one in dracut-lib.sh, also makes an archive of
// them look like a shell script, so that the archive read as one file is
// scanned.
var reverseShellParts = []struct{ name, body string }{
	{"usr/lib/net.pl", "#!/usr/bin/perl\nuse Socket;\nsocket(my $s, PF_INET, SOCK_STREAM, 0) or die;\nopen(my $fh, '<', '/etc/hosts') or die;\n"},
	{"usr/lib/log.sh", "#!/bin/sh\necho \"warning\">&2\n"},
	{"usr/lib/emergency.sh", "#!/bin/sh\nemergency_shell() {\n    if [ -n \"$1\" ]; then\n        exec sh -i\n    fi\n}\n"},
}

// reverseShellCPIO returns a newc cpio archive holding reverseShellParts.
func reverseShellCPIO(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	cw := cpio.NewWriter(&buf)
	for _, p := range reverseShellParts {
		if err := cw.WriteHeader(&cpio.Header{Name: p.name, Mode: cpio.TypeReg | 0o755, Size: int64(len(p.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := cw.Write([]byte(p.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := cw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestScanCPIOMembersSeparately checks that a cpio archive, such as a Linux
// initramfs, is scanned member by member: strings from unrelated members must
// not combine into one match, as when the whole archive was scanned as one
// file and a dracut initramfs was reported as a Perl reverse shell.
func TestScanCPIOMembersSeparately(t *testing.T) {
	t.Parallel()
	td := t.TempDir()

	var all strings.Builder
	for _, p := range reverseShellParts {
		all.WriteString(p.body)
	}
	archive := reverseShellCPIO(t)
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	compressed := enc.EncodeAll(archive, nil)
	_ = enc.Close()

	fixtures := map[string][]byte{
		// The control: the members' content in one file matches the rule.
		"together.pl":    []byte(all.String()),
		"initramfs.cpio": archive,
		"initramfs.img":  compressed,
	}
	for name, data := range fixtures {
		if err := file.WriteFileIn(td, name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for name := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := scanRuleNames(t, filepath.Join(td, name))
			matched := []string{}
			for path, rules := range got {
				if _, ok := rules["perl_reverse_shell"]; ok {
					matched = append(matched, path)
				}
			}
			want := name == "together.pl"
			if (len(matched) > 0) != want {
				t.Errorf("perl_reverse_shell matched %v; want a match = %v (reports: %v)", matched, want, got)
			}
			// The members are still scanned, each on its own.
			if _, ok := got["net.pl"]; !want && !ok {
				t.Errorf("member net.pl was not reported; reports: %v", got)
			}
		})
	}
}
