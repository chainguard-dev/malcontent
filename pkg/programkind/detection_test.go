// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/google/go-cmp/cmp"
)

// programkindRoot opens a root on dir that stays open until the test ends.
func programkindRoot(tb testing.TB, dir string) *os.Root {
	tb.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		tb.Fatalf("OpenRoot(%q): %v", dir, err)
	}
	tb.Cleanup(func() { _ = r.Close() })
	return r
}

// programkindOpenFilesUnder counts this process's open file descriptors that
// refer to paths beneath dir. It reads /proc/self/fd and skips the test where
// that is unavailable.
func programkindOpenFilesUnder(t *testing.T, dir string) int {
	t.Helper()
	fds, err := os.OpenRoot("/proc/self/fd")
	if err != nil {
		t.Skipf("open file descriptors are not listable: %v", err)
	}
	defer fds.Close()
	entries, err := fs.ReadDir(fds.FS(), ".")
	if err != nil {
		t.Skipf("open file descriptors are not listable: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, err)
	}
	prefix := resolved + string(filepath.Separator)
	n := 0
	for _, e := range entries {
		target, err := fds.Readlink(e.Name())
		if err == nil && strings.HasPrefix(target, prefix) {
			n++
		}
	}
	return n
}

func TestFileClosesTheFile(t *testing.T) {
	t.Parallel()
	script := []byte("#!/bin/sh\necho closed\n")
	tests := []struct {
		name    string
		content []byte
	}{
		{"small file", script},
		// Several MiB, read into one of the larger pooled buffers.
		{"large file", append(script, bytes.Repeat([]byte("echo large\n"), 4<<20/11)...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFixture(t, "closed.sh", tt.content)
			if _, err := File(t.Context(), path); err != nil {
				t.Fatalf("File(%q) error: %v", path, err)
			}
			if n := programkindOpenFilesUnder(t, filepath.Dir(path)); n != 0 {
				t.Errorf("open files after File: got = %d, want = 0", n)
			}
		})
	}
}

func TestFileReleasesLargeFileMapping(t *testing.T) {
	t.Parallel()
	// Files larger than 32,000,000 bytes are memory-mapped for detection. A
	// sparse file keeps the test from writing that much.
	const size = 32_000_001
	path := writeFixture(t, "large", []byte{0x7f, 'E', 'L', 'F'})
	w, err := file.OpenFileIn(filepath.Dir(path), filepath.Base(path), os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("Open(%q) for writing: %v", path, err)
	}
	err = w.Truncate(size)
	_ = w.Close()
	if err != nil {
		t.Fatalf("Truncate(%q, %d): %v", path, size, err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", path, err)
	}

	got, err := File(t.Context(), path)
	if err != nil {
		t.Fatalf("File(%q) error: %v", path, err)
	}
	if diff := cmp.Diff(&FileType{Ext: "elf", MIME: "application/x-elf"}, got); diff != "" {
		t.Errorf("File(%q) mismatch (-want +got):\n%s", path, diff)
	}
	maps, err := file.ReadFileIn("/proc/self", "maps")
	if err != nil {
		t.Skipf("memory mappings are not listable: %v", err)
	}
	if strings.Contains(string(maps), resolved) {
		t.Errorf("mapping of %q after File: got = present, want = absent", resolved)
	}
}

func TestFileReportsUnreadableFiles(t *testing.T) {
	t.Parallel()

	t.Run("file without read permission", func(t *testing.T) {
		t.Parallel()
		path := writeFixture(t, "locked.sh", []byte("#!/bin/sh\necho locked\n"))
		r := programkindRoot(t, filepath.Dir(path))
		if err := r.Chmod("locked.sh", 0); err != nil {
			t.Fatalf("Chmod(%q): %v", path, err)
		}
		if f, err := r.Open("locked.sh"); err == nil {
			_ = f.Close()
			t.Skip("file permissions do not restrict this user")
		}
		got, err := File(t.Context(), path)
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("File(%q) error: got = %v, want = %v", path, err, fs.ErrPermission)
		}
		if got != nil {
			t.Errorf("File(%q): got = %+v, want = nil", path, got)
		}
	})

	t.Run("regular file whose read fails", func(t *testing.T) {
		t.Parallel()
		// Linux reports a loopback interface's speed as a non-empty regular
		// file whose read fails with EINVAL.
		const path = "/sys/class/net/lo/speed"
		st, err := file.Stat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			t.Skipf("%s is not a non-empty regular file here: %v", path, err)
		}
		_, readErr := file.ReadFile(path)
		var pathErr *fs.PathError
		if !errors.As(readErr, &pathErr) || pathErr.Op != "read" {
			t.Skipf("%s does not fail to read here: %v", path, readErr)
		}
		got, err := File(t.Context(), path)
		if !errors.Is(err, pathErr.Err) {
			t.Errorf("File(%q) error: got = %v, want = %v", path, err, pathErr.Err)
		}
		if got != nil {
			t.Errorf("File(%q): got = %+v, want = nil", path, got)
		}
	})
}

// upxStub writes a shell script that stands in for the UPX binary and returns
// its path. The script prints output and exits with code, which lets tests
// drive IsValidUPX through MALCONTENT_UPX_PATH without a real UPX install.
// output must not contain single quotes.
func upxStub(t *testing.T, output string, code int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("UPX stub requires a POSIX shell")
	}
	dir := t.TempDir()
	r := programkindRoot(t, dir)
	p := filepath.Join(dir, "upx")
	script := "#!/bin/sh\necho '" + output + "'\nexit " + strconv.Itoa(code) + "\n"
	if err := r.WriteFile("upx", []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile(%q): %v", p, err)
	}
	if err := r.Chmod("upx", 0o700); err != nil {
		t.Fatalf("Chmod(%q): %v", p, err)
	}
	return p
}

// writeFixture writes content to rel beneath a fresh temporary directory and
// returns the full path.
func writeFixture(tb testing.TB, rel string, content []byte) string {
	tb.Helper()
	dir := tb.TempDir()
	p := filepath.Join(dir, rel)
	if err := file.MkdirAllIn(dir, filepath.Dir(rel), 0o700); err != nil {
		tb.Fatalf("MkdirAll(%q): %v", filepath.Dir(p), err)
	}
	if err := file.WriteFileIn(dir, rel, content, 0o600); err != nil {
		tb.Fatalf("WriteFile(%q): %v", p, err)
	}
	return p
}

func TestUPXInstalled(t *testing.T) {
	// Not parallel: subtests set MALCONTENT_UPX_PATH for the whole process.
	stub := upxStub(t, "", 0)
	resolved, err := filepath.EvalSymlinks(stub)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", stub, err)
	}

	tests := []struct {
		name     string
		env      string
		wantPath string
		wantErr  error
	}{
		{"operator path outside the allowlist is trusted", stub, resolved, nil},
		{"relative operator path is invalid", "bin/upx", "", ErrUPXPathInvalid},
		{"missing operator path is invalid", filepath.Join(t.TempDir(), "missing-upx"), "", ErrUPXPathInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MALCONTENT_UPX_PATH", tt.env)
			got, err := UPXInstalled()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("UPXInstalled() error: got = %v, want = %v", err, tt.wantErr)
			}
			if got != tt.wantPath {
				t.Errorf("UPXInstalled() path: got = %q, want = %q", got, tt.wantPath)
			}
		})
	}

	t.Run("unset operator path uses automatic discovery", func(t *testing.T) {
		t.Setenv("MALCONTENT_UPX_PATH", "")
		want, wantErr := validateUPXPath(defaultUPXPath, false)
		got, err := UPXInstalled()
		if wantErr != nil {
			if !errors.Is(err, ErrUPXNotFound) || errors.Is(err, ErrUPXPathInvalid) {
				t.Errorf("UPXInstalled() error: got = %v, want = %v", err, ErrUPXNotFound)
			}
			return
		}
		if err != nil || got != want {
			t.Errorf("UPXInstalled(): got = %q, %v, want = %q, nil", got, err, want)
		}
	})
}

func TestUPXInstalledCachesUntilThePathChanges(t *testing.T) {
	// Not parallel: t.Setenv sets MALCONTENT_UPX_PATH for the whole process.
	stub := upxStub(t, "", 0)
	resolved, err := filepath.EvalSymlinks(stub)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", stub, err)
	}

	t.Setenv("MALCONTENT_UPX_PATH", stub)
	if got, err := UPXInstalled(); err != nil || got != resolved {
		t.Fatalf("UPXInstalled(): got = %q, %v, want = %q, nil", got, err, resolved)
	}

	// A world-writable binary fails validation, but while the setting is
	// unchanged the earlier result stands.
	if err := programkindRoot(t, filepath.Dir(stub)).Chmod(filepath.Base(stub), 0o777); err != nil {
		t.Fatalf("Chmod(%q): %v", stub, err)
	}
	if got, err := UPXInstalled(); err != nil || got != resolved {
		t.Errorf("UPXInstalled() with the setting unchanged: got = %q, %v, want = %q, nil", got, err, resolved)
	}

	// Any change to the setting validates afresh, even a change back.
	t.Setenv("MALCONTENT_UPX_PATH", "bin/upx")
	if _, err := UPXInstalled(); !errors.Is(err, ErrUPXPathInvalid) {
		t.Errorf("UPXInstalled() with a relative path: got = %v, want = %v", err, ErrUPXPathInvalid)
	}
	t.Setenv("MALCONTENT_UPX_PATH", stub)
	if _, err := UPXInstalled(); !errors.Is(err, ErrUPXPathInvalid) {
		t.Errorf("UPXInstalled() after the setting changed back: got = %v, want = %v", err, ErrUPXPathInvalid)
	}
}

func TestIsValidUPX(t *testing.T) {
	// Not parallel: subtests set MALCONTENT_UPX_PATH for the whole process.
	packed := []byte("\x7fELF\x02\x01\x01\x00UPX!payload")
	dir := t.TempDir()
	target := filepath.Join(dir, "packed")

	tests := []struct {
		name    string
		content []byte
		path    string
		output  string
		code    int
		want    bool
		wantErr bool
	}{
		{"content without the UPX marker", []byte("plain"), target, "", 0, false, false},
		{"successful listing", packed, target, "", 0, true, false},
		{"failed listing without a not-packed message", packed, target, "upx: packed: CantUnpackException: header corrupted", 1, true, false},
		{"failed listing with NotPackedException only", packed, target, "upx: packed: NotPackedException", 2, false, false},
		{"failed listing with not packed by UPX only", packed, target, "upx: packed: not packed by UPX", 2, false, false},
		{"failed listing with the full not-packed message", packed, target, "upx: packed: NotPackedException: not packed by UPX", 2, false, false},
		{"successful listing that mentions not packed", packed, target, "NotPackedException: not packed by UPX", 0, true, false},
		{"file name beginning with a dash", packed, filepath.Join(dir, "-packed"), "", 0, false, true},
		{"relative path beginning with a dash", packed, "-dir/packed", "", 0, false, true},
		{"file name of 255 bytes", packed, filepath.Join(dir, strings.Repeat("a", 255)), "", 0, true, false},
		{"file name of 256 bytes", packed, filepath.Join(dir, strings.Repeat("a", 256)), "", 0, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MALCONTENT_UPX_PATH", upxStub(t, tt.output, tt.code))
			got, err := IsValidUPX(t.Context(), tt.content, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsValidUPX() error: got = %v, want error = %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("IsValidUPX(): got = %v, want = %v", got, tt.want)
			}
		})
	}

	t.Run("invalid operator UPX path", func(t *testing.T) {
		t.Setenv("MALCONTENT_UPX_PATH", "bin/upx")
		got, err := IsValidUPX(t.Context(), packed, target)
		if !errors.Is(err, ErrUPXPathInvalid) {
			t.Errorf("IsValidUPX() error: got = %v, want = %v", err, ErrUPXPathInvalid)
		}
		if got {
			t.Errorf("IsValidUPX(): got = %v, want = false", got)
		}
	})

	t.Run("relative path after the working directory is removed", func(t *testing.T) {
		t.Setenv("MALCONTENT_UPX_PATH", upxStub(t, "", 0))
		parent := t.TempDir()
		r := programkindRoot(t, parent)
		gone := filepath.Join(parent, "gone")
		if err := r.Mkdir("gone", 0o700); err != nil {
			t.Fatalf("Mkdir(%q): %v", gone, err)
		}
		t.Chdir(gone)
		if err := r.Remove("gone"); err != nil {
			t.Fatalf("Remove(%q): %v", gone, err)
		}
		if _, err := filepath.Abs("packed"); err == nil {
			t.Skip("relative paths still resolve after the working directory is removed")
		}
		got, err := IsValidUPX(t.Context(), packed, "packed")
		if err == nil {
			t.Errorf("IsValidUPX() error: got = nil, want the path resolution error")
		}
		if got {
			t.Errorf("IsValidUPX(): got = %v, want = false", got)
		}
	})
}

func TestFileAndIsSupportedArchiveDetectUPX(t *testing.T) {
	// Not parallel: t.Setenv sets MALCONTENT_UPX_PATH for the whole process.
	t.Setenv("MALCONTENT_UPX_PATH", upxStub(t, "", 0))
	packed := writeFixture(t, "packed", []byte("\x7fELF\x02\x01\x01\x00UPX!payload"))
	script := writeFixture(t, "notes", []byte("#!/bin/sh\necho hello\n"))

	got, err := File(t.Context(), packed)
	if err != nil {
		t.Fatalf("File(%q) error: %v", packed, err)
	}
	if diff := cmp.Diff(&FileType{Ext: "upx", MIME: "application/x-upx"}, got); diff != "" {
		t.Errorf("File(%q) mismatch (-want +got):\n%s", packed, diff)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"UPX-packed file without an archive extension", packed, true},
		{"shell script without an archive extension", script, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSupportedArchive(t.Context(), tt.path); got != tt.want {
				t.Errorf("IsSupportedArchive(%q): got = %v, want = %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestFileSkipsPathsWithoutContent(t *testing.T) {
	t.Parallel()
	empty := writeFixture(t, "empty.sh", nil)
	dir := filepath.Dir(empty)
	dangling := filepath.Join(dir, "dangling.sh")
	if err := programkindRoot(t, dir).Symlink(filepath.Join(dir, "missing-target.sh"), "dangling.sh"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"directory", dir},
		{"empty file with a supported extension", empty},
		{"path that does not exist", filepath.Join(dir, "missing.sh")},
		{"symlink to a path that does not exist", dangling},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := File(t.Context(), tt.path)
			if err != nil {
				t.Errorf("File(%q) error: got = %v, want = nil", tt.path, err)
			}
			if got != nil {
				t.Errorf("File(%q): got = %+v, want = nil", tt.path, got)
			}
		})
	}
}

func TestFileContentFallback(t *testing.T) {
	t.Parallel()
	binaryPHP := append([]byte{0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15}, "<?php echo 1; ?>\n"...)
	requireJS := []byte("const fs = require('fs');\n")

	tests := []struct {
		name    string
		rel     string
		content []byte
		want    *FileType
	}{
		{"binary data with a two-letter unknown extension is skipped", "blob.qz", binaryPHP, nil},
		{"binary data with a one-letter unknown extension is inspected", "blob.q", binaryPHP, &FileType{Ext: "php", MIME: "text/x-php"}},
		{"plain text with an unknown extension is inspected", "loader.qz", requireJS, &FileType{Ext: "js", MIME: "application/javascript"}},
		{"plain text man page is skipped", "usr/share/man/man1/loader.1", requireJS, nil},
		{"binary data under a man page name is inspected", "usr/share/man/man1/blob.1", binaryPHP, &FileType{Ext: "php", MIME: "text/x-php"}},
		{"text with a tracked data extension is skipped", "usage.md", []byte("# Usage\n\nconst fs = require('fs');\n"), nil},
		{"Python import without an extension", "tool", []byte("import os\nprint(os.getcwd())\n"), &FileType{Ext: "py", MIME: "text/x-python"}},
		{"unknown interpreter line without an extension", "tool", []byte("#!/opt/custom/interp\nrun\n"), &FileType{Ext: "script", MIME: "text/x-generic-script"}},
		{"C include without an extension", "header", []byte("#include <stdio.h>\n"), &FileType{Ext: "c", MIME: "text/x-c"}},
		{"Erlang BEAM without an extension", "module", []byte("FOR1\x00\x00\x00\x40BEAMAtU8\x00\x00\x00\x10"), &FileType{Ext: "beam", MIME: "application/x-erlang-binary"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFixture(t, tt.rel, tt.content)
			got, err := File(t.Context(), path)
			if err != nil {
				t.Fatalf("File(%q) error: %v", path, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("File(%q) mismatch (-want +got):\n%s", path, diff)
			}
		})
	}
}

func TestMakeFileTypeMIMECorrections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		ext  string
		mime string
		want *FileType
	}{
		{"shared library MIME without .so in the path is an ELF executable", "bin/tool", "so", "application/x-sharedlib", &FileType{Ext: "elf", MIME: "application/x-elf"}},
		{"shared library MIME with .so in the path is kept", "lib/libfoo.so.1", "so", "application/x-sharedlib", &FileType{Ext: "so", MIME: "application/x-sharedlib"}},
		{"shell MIME with .js in the path is JavaScript", "dist/tool.js", "sh", mimeShellScript, &FileType{Ext: "js", MIME: "application/javascript"}},
		{"shell MIME without .js in the path is kept", "bin/tool.sh", "sh", mimeShellScript, &FileType{Ext: "sh", MIME: mimeShellScript}},
		{"extension without a tracked MIME is not a program", "notes.txt", "txt", "text/plain", nil},
		{"data extension with an application MIME is not a program", "report.pdf", "pdf", "application/pdf", nil},
		{"tracked extension with an application MIME is kept", "auto.scpt", "scpt", "application/x-applescript", &FileType{Ext: "scpt", MIME: "application/x-applescript"}},
		{"tracked extension with an untracked MIME family is rejected", "image.sh", "sh", "image/png", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := makeFileType(tt.path, tt.ext, tt.mime)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("makeFileType(%q, %q, %q) mismatch (-want +got):\n%s", tt.path, tt.ext, tt.mime, diff)
			}
		})
	}
}

func TestIsLikelyManPage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"numbered section under usr/share/man", "/usr/share/man/man7/parallel_examples.7", true},
		{"extracted image path under usr/share/man", "rootfs/usr/share/man/man1/ls.1", true},
		{"non-numeric extension under usr/share/man", "/usr/share/man/man1/index.html", false},
		{"no extension under usr/share/man", "/usr/share/man/README", false},
		{"numbered extension outside usr/share/man", "/opt/tool/notes.7", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isLikelyManPage(tt.path); got != tt.want {
				t.Errorf("isLikelyManPage(%q): got = %v, want = %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestValidateUPXPathDiscoveryRejectsArbitraryBinDirectory(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits required for the UPX path checks")
	}
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := file.MkdirAllIn(tmp, "bin", 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", binDir, err)
	}
	bin := writeExecutable(t, binDir, "upx", 0o755)

	if got, err := validateUPXPath(bin, false); err == nil {
		t.Errorf("validateUPXPath(%q, false): got = %q, want an allowlist error", bin, got)
	}
}
