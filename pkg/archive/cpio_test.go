// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// newcCRC returns archive, a newc cpio archive whose bodies hold no magic,
// with every header given the newc-with-checksums magic.
func newcCRC(archive []byte) []byte {
	return bytes.ReplaceAll(archive, []byte("070701"), []byte("070702"))
}

func TestSniffKindCPIO(t *testing.T) {
	t.Parallel()
	newc := pkgsCPIO(t, []pkgsCPIOEntry{{name: "./a", mode: cpio.TypeReg | 0o644, body: "a"}})
	odc := append([]byte("070707"), bytes.Repeat([]byte("0"), 70)...)
	tests := []struct {
		name string
		data []byte
		want archiveKind
	}{
		{name: "newc", data: newc, want: kindCPIO},
		{name: "newc with checksums", data: newcCRC(newc), want: kindCPIO},
		// cavaliergopher/cpio reads only the SVR4 formats.
		{name: "old portable format is not read", data: odc, want: kindUnknown},
		{name: "magic followed by text", data: []byte("070701 is a number and so is " + strings.Repeat("this ", 30)), want: kindUnknown},
		{name: "magic alone", data: []byte("070701"), want: kindUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sniffKind(bytes.NewReader(tt.data), int64(len(tt.data))); got != tt.want {
				t.Errorf("sniffKind: got = %v, want = %v", got, tt.want)
			}
		})
	}
	if extractorForKind(kindCPIO, "") == nil || ExtractionMethod(".cpio") == nil {
		t.Error("no extractor for cpio")
	}
}

func TestExtractCPIOMembers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    []byte
		want    map[string]string
		wantErr bool
	}{
		{
			name: "files, directories, and symlinks",
			data: pkgsCPIO(t, []pkgsCPIOEntry{
				{name: ".", mode: cpio.TypeDir | 0o755},
				{name: "usr", mode: cpio.TypeDir | 0o755},
				{name: "usr/bin", mode: cpio.TypeDir | 0o755},
				{name: "usr/bin/tool", mode: cpio.TypeReg | 0o755, body: rpmTool},
				{name: "bin", mode: cpio.TypeSymlink | 0o777, body: "usr/bin"},
				{name: "dev", mode: cpio.TypeDir | 0o755},
				{name: "dev/console", mode: cpio.TypeChar | 0o600},
				{name: "init", mode: cpio.TypeReg | 0o755, body: "#!/bin/sh\nexec /usr/bin/tool\n"},
			}),
			want: map[string]string{
				"usr":          "/",
				"usr/bin":      "/",
				"usr/bin/tool": rpmTool,
				"bin":          "-> usr/bin",
				"dev":          "/",
				"init":         "#!/bin/sh\nexec /usr/bin/tool\n",
			},
		},
		{
			// newc stores a hard link set's content with its last member.
			name: "hard links",
			data: pkgsCPIO(t, []pkgsCPIOEntry{
				{name: "usr/bin/a", mode: cpio.TypeReg | 0o755, links: 2, inode: 9},
				{name: "usr/bin/b", mode: cpio.TypeReg | 0o755, body: benignMarker, links: 2, inode: 9},
			}),
			want: map[string]string{"usr": "/", "usr/bin": "/", "usr/bin/a": benignMarker, "usr/bin/b": benignMarker},
		},
		{
			name: "newc with checksums",
			data: newcCRC(pkgsCPIO(t, []pkgsCPIOEntry{{name: "a", mode: cpio.TypeReg | 0o644, body: "a"}})),
			want: map[string]string{"a": "a"},
		},
		{
			name: "names leaving the root are extracted beneath it",
			data: pkgsCPIO(t, []pkgsCPIOEntry{
				{name: "../../escape", mode: cpio.TypeReg | 0o644, body: "x"},
				{name: "/abs", mode: cpio.TypeReg | 0o644, body: "y"},
				{name: "a/../../b", mode: cpio.TypeReg | 0o644, body: "z"},
			}),
			want: map[string]string{"escape": "x", "abs": "y", "b": "z"},
		},
		{
			name: "symlink leaving the root is skipped",
			data: pkgsCPIO(t, []pkgsCPIOEntry{
				{name: "esc", mode: cpio.TypeSymlink | 0o777, body: "../../outside"},
				{name: "esc/passwd", mode: cpio.TypeReg | 0o644, body: "p"},
			}),
			want: map[string]string{"esc": "/", "esc/passwd": "p"},
		},
		{
			name:    "archive ending inside a header is an error",
			data:    pkgsCPIO(t, []pkgsCPIOEntry{{name: "a", mode: cpio.TypeReg | 0o644, body: "a"}})[:150],
			want:    map[string]string{"a": "a"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "initramfs.cpio", tt.data)
			out := filepath.Join(t.TempDir(), "out")
			err := ExtractCPIO(t.Context(), out, src)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCPIO error: got = %v, want error = %v", err, tt.wantErr)
			}
			wantTree(t, out, tt.want)
		})
	}
}

func TestExtractCPIOConcatenated(t *testing.T) {
	t.Parallel()
	early := pkgsCPIO(t, []pkgsCPIOEntry{
		{name: "kernel", mode: cpio.TypeDir | 0o755},
		{name: "kernel/x86/microcode/AuthenticAMD.bin", mode: cpio.TypeReg | 0o644, body: "ucode"},
	})
	main := pkgsCPIO(t, []pkgsCPIOEntry{
		{name: "init", mode: cpio.TypeReg | 0o755, body: "#!/bin/sh\n"},
		// A later archive's member of a name an earlier one took is kept
		// beside it, not in its place.
		{name: "kernel/x86/microcode/AuthenticAMD.bin", mode: cpio.TypeReg | 0o644, body: "later"},
	})
	third := newcCRC(pkgsCPIO(t, []pkgsCPIOEntry{{name: "etc/conf", mode: cpio.TypeReg | 0o644, body: "c"}}))
	want := map[string]string{
		"kernel":                                "/",
		"kernel/x86":                            "/",
		"kernel/x86/microcode":                  "/",
		"kernel/x86/microcode/AuthenticAMD.bin": "ucode",
		"kernel/x86/microcode/AuthenticAMD_1.bin": "later",
		"init":     "#!/bin/sh\n",
		"etc":      "/",
		"etc/conf": "c",
	}
	tests := []struct {
		name string
		data []byte
	}{
		{name: "back to back", data: slices.Concat(early, main, third)},
		// The kernel's own early microcode archive is padded out to a block.
		{name: "padded with NUL bytes", data: slices.Concat(early, make([]byte, 512-len(early)%512), main, make([]byte, 4096), third, make([]byte, 3))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "initramfs.img", tt.data)
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractCPIO(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractCPIO: %v", err)
			}
			wantTree(t, out, want)
		})
	}
}

func TestExtractCPIOWritesTrailingData(t *testing.T) {
	t.Parallel()
	early := pkgsCPIO(t, []pkgsCPIOEntry{{name: "early", mode: cpio.TypeReg | 0o644, body: "ucode"}})
	compressed := pkgsCompress(t, pkgsZstd, pkgsCPIO(t, []pkgsCPIOEntry{{name: "init", mode: cpio.TypeReg | 0o755, body: rpmTool}}))
	odc := append([]byte("070707"), bytes.Repeat([]byte("0"), 120)...)
	tests := []struct {
		name string
		data []byte
		want map[string]string
	}{
		{
			name: "compressed second segment",
			data: slices.Concat(early, make([]byte, 508), compressed),
			want: map[string]string{"early": "ucode", cpioTrailingName: string(compressed)},
		},
		{
			name: "text after the trailer",
			data: slices.Concat(early, []byte(benignMarker)),
			want: map[string]string{"early": "ucode", cpioTrailingName: benignMarker},
		},
		{
			name: "archive in a format the reader does not read",
			data: slices.Concat(early, odc),
			want: map[string]string{"early": "ucode", cpioTrailingName: string(odc)},
		},
		{
			name: "member of the same name keeps it",
			data: slices.Concat(pkgsCPIO(t, []pkgsCPIOEntry{{name: cpioTrailingName, mode: cpio.TypeReg | 0o644, body: "member"}}), []byte(benignMarker)),
			want: map[string]string{cpioTrailingName: "member", "malcontent-cpio-trailing_1.bin": benignMarker},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "initramfs.img", tt.data)
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractCPIO(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractCPIO: %v", err)
			}
			wantTree(t, out, tt.want)
		})
	}
}

func TestExtractCPIOBudget(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("A", 64<<10)
	archive := pkgsCPIO(t, []pkgsCPIOEntry{
		{name: "a", mode: cpio.TypeReg | 0o644, body: body},
		{name: "b", mode: cpio.TypeReg | 0o644, body: body},
	})
	tests := []struct {
		name string
		data []byte
	}{
		{name: "members", data: archive},
		{name: "members of a later archive", data: slices.Concat(pkgsCPIO(t, nil), archive)},
		{name: "trailing data", data: slices.Concat(pkgsCPIO(t, nil), []byte(body), []byte(body))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := malcontent.ContextWithConfig(t.Context(), &malcontent.Config{MaxArchiveBytes: 96 << 10})
			src := writeTemp(t, "initramfs.cpio", tt.data)
			err := ExtractCPIO(ctx, filepath.Join(t.TempDir(), "out"), src)
			if !errors.Is(err, file.ErrArchiveBytesCap) {
				t.Errorf("ExtractCPIO error: got = %v, want = %v", err, file.ErrArchiveBytesCap)
			}
		})
	}
}

// TestExtractArchiveToTempDirSplitsInitramfs extracts an initramfs as the
// kernel reads it, whatever it is named: each member becomes a file of its
// own, so that no file holds the content of two members.
func TestExtractArchiveToTempDirSplitsInitramfs(t *testing.T) {
	t.Parallel()
	first, second := "#!/bin/sh\n# first "+benignMarker+"\n", "#!/bin/sh\n# second "+benignMarker+"\n"
	main := pkgsCPIO(t, []pkgsCPIOEntry{
		{name: "usr/lib/first.sh", mode: cpio.TypeReg | 0o755, body: first},
		{name: "usr/lib/second.sh", mode: cpio.TypeReg | 0o755, body: second},
	})
	early := pkgsCPIO(t, []pkgsCPIOEntry{{name: "kernel/x86/microcode/GenuineIntel.bin", mode: cpio.TypeReg | 0o644, body: "ucode"}})
	tests := []struct {
		name string
		file string
		data []byte
		want []string
	}{
		{name: "zstd compressed", file: "initramfs.img", data: pkgsCompress(t, pkgsZstd, main), want: []string{first, second}},
		{name: "gzip compressed", file: "initrd", data: pkgsCompress(t, pkgsGzip, main), want: []string{first, second}},
		{name: "uncompressed", file: "initramfs.cpio", data: main, want: []string{first, second}},
		{
			name: "early microcode before a compressed archive",
			file: "initramfs.img",
			data: slices.Concat(early, make([]byte, 512-len(early)%512), pkgsCompress(t, pkgsZstd, main)),
			want: []string{"ucode", first, second},
		},
		{
			name: "compressed archive holding archives back to back",
			file: "initramfs.img",
			data: pkgsCompress(t, pkgsZstd, slices.Concat(early, main)),
			want: []string{"ucode", first, second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, tt.file, tt.data)
			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
			if err != nil {
				t.Fatalf("ExtractArchiveToTempDir: %v", err)
			}
			defer cleanupTempDir(t.Context(), dir)
			got := slices.Collect(maps.Values(treeContents(t, dir)))
			for _, w := range tt.want {
				if !slices.Contains(got, w) {
					t.Errorf("no file holds %q; tree = %q", w, treeContents(t, dir))
				}
			}
			for _, g := range got {
				if strings.Contains(g, first) && strings.Contains(g, second) {
					t.Errorf("a file holds both members: %q", g)
				}
			}
		})
	}
}
