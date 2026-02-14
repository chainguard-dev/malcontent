// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// maxFuzzSize is the maximum input size for fuzz tests to stay well under
// Go's 100MB fuzzer shared memory capacity and avoid OOM in parsers.
const maxFuzzSize = 10 * 1024 * 1024

// FuzzFile tests file type detection with random inputs.
func FuzzFile(f *testing.F) {
	const maxSeedSize int64 = maxFuzzSize

	samplesDir := "../../out/chainguard-sandbox/malcontent-samples"
	err := filepath.WalkDir(samplesDir, func(path string, d os.DirEntry, _ error) error {
		if d == nil || d.IsDir() {
			return nil
		}
		if filepath.Base(path)[0] == '.' {
			return nil
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		if info.Size() > maxSeedSize {
			return nil
		}

		if fp, readErr := os.Open(path); readErr == nil {
			buf := make([]byte, file.ExtractBuffer)
			if data, contentsErr := file.GetContents(fp, buf); contentsErr == nil {
				f.Add(data, filepath.Base(path))
			}
			fp.Close()
		}
		return nil
	})
	if err != nil {
		f.Logf("Could not walk samples directory: %v", err)
	}

	f.Add([]byte{0x7f, 0x45, 0x4c, 0x46}, "test.elf")                 // ELF magic
	f.Add([]byte{0x4d, 0x5a}, "test.exe")                             // PE/MZ magic
	f.Add([]byte{0xca, 0xfe, 0xba, 0xbe}, "test.macho")               // Mach-O magic
	f.Add([]byte{0x1f, 0x8b, 0x08}, "test.gz")                        // gzip magic
	f.Add([]byte{0x50, 0x4b, 0x03, 0x04}, "test.zip")                 // zip magic
	f.Add([]byte("#!/bin/sh\necho hello"), "test.sh")                 // shell script
	f.Add([]byte("#!/usr/bin/env python\nprint('hello')"), "test.py") // python script
	f.Add([]byte("<?php\necho 'hello';"), "test.php")                 // PHP
	f.Add([]byte("#include <stdio.h>\nint main() {}"), "test.c")      // C code
	f.Add([]byte("package main\nfunc main() {}"), "test.go")          // Go code
	f.Add([]byte(""), "empty")                                        // empty file
	f.Add([]byte{0x00, 0x00, 0x00, 0x00}, "nulls")                    // null bytes
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, "ones")                     // all ones
	f.Add([]byte("UPX!"), "test.upx")                                 // UPX magic

	f.Fuzz(func(t *testing.T, data []byte, filename string) {
		if len(data) > maxFuzzSize {
			return
		}
		if len(filename) > 255 || filepath.Clean(filename) != filename {
			return
		}

		tmpFile, err := os.CreateTemp("", "fuzz-file-*-"+filepath.Base(filename))
		if err != nil {
			t.Skip("failed to create temp file")
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip("failed to write to temp file")
		}
		tmpFile.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		ft, err := File(ctx, tmpFile.Name())

		_ = ft
		_ = err

		if ft != nil {
			if len(ft.MIME) > 1000 {
				t.Fatalf("MIME type too long: %d bytes", len(ft.MIME))
			}
			if len(ft.Ext) > 100 {
				t.Fatalf("Extension too long: %d bytes", len(ft.Ext))
			}
		}
	})
}

// FuzzPath tests the Path() function which determines file type from path/extension.
func FuzzPath(f *testing.F) {
	f.Add("test.sh")
	f.Add("test.py")
	f.Add("test.go")
	f.Add("test.c")
	f.Add("test.js")
	f.Add("test.rb")
	f.Add("test.elf")
	f.Add("test.exe")
	f.Add("test.dll")
	f.Add("test.so")
	f.Add("test.tar.gz")
	f.Add("test.zip")
	f.Add("../../../etc/passwd")
	f.Add("test")
	f.Add("")
	f.Add("test....")
	f.Add(".hidden")
	f.Add("test.a.b.c.d.e")

	f.Fuzz(func(t *testing.T, path string) {
		ft := Path(path)

		if ft != nil {
			if len(ft.MIME) > 1000 {
				t.Fatalf("MIME type too long: %d bytes", len(ft.MIME))
			}
			if len(ft.Ext) > 100 {
				t.Fatalf("Extension too long: %d bytes", len(ft.Ext))
			}
		}
	})
}

// FuzzGetExt tests the GetExt() function which extracts file extensions.
func FuzzGetExt(f *testing.F) {
	f.Add("test.tar.gz")
	f.Add("test.tar.xz")
	f.Add("test.tar.bz2")
	f.Add("test.zip")
	f.Add("test")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("...")
	f.Add("/path/to/file.tar.gz")
	f.Add("file_1.0.0.tar.gz")
	f.Add("file.a.b.c")

	f.Fuzz(func(t *testing.T, path string) {
		ext := GetExt(path)

		if ext != "" && ext[0] != '.' {
			t.Fatalf("extension doesn't start with dot: %q", ext)
		}
	})
}

// FuzzIsSupportedArchive tests the IsSupportedArchive function with random paths.
func FuzzIsSupportedArchive(f *testing.F) {
	// Seed with all known archive extensions
	for ext := range ArchiveMap {
		f.Add("file" + ext)
	}
	f.Add("not_an_archive")
	f.Add("")
	f.Add("file.txt")
	f.Add("file.tar.gz")
	f.Add("file.TAR.GZ")     // case variation
	f.Add("file.tar.gz.bak") // double extension
	f.Add("archive")         // no extension

	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 4096 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		result := IsSupportedArchive(ctx, path)

		// If the extension is in ArchiveMap, result must be true
		ext := GetExt(path)
		if ArchiveMap[ext] && !result {
			t.Errorf("IsSupportedArchive(%q) = false, but ext %q is in ArchiveMap", path, ext)
		}

		_ = result // no panics
	})
}

// FuzzIsValidUPX tests the IsValidUPX function with random file contents.
func FuzzIsValidUPX(f *testing.F) {
	f.Add([]byte{}, "/tmp/test")
	f.Add([]byte("UPX!"), "/tmp/test")
	f.Add([]byte("not upx"), "/tmp/test")
	f.Add([]byte{0x7f, 0x45, 0x4c, 0x46, 'U', 'P', 'X', '!'}, "/tmp/elf_upx")
	f.Add([]byte("UPX!extra"), "/tmp/test")

	f.Fuzz(func(t *testing.T, data []byte, path string) {
		if len(data) > maxFuzzSize {
			return
		}
		// Avoid paths that start with "-" (rejected by the function)
		if strings.HasPrefix(path, "-") || path == "" {
			return
		}
		// Avoid long filenames
		if len(filepath.Base(path)) > 255 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		valid, err := IsValidUPX(ctx, data, path)

		// If data doesn't contain "UPX!" magic, result must be false
		if !bytes.Contains(data, []byte("UPX!")) {
			if valid {
				t.Error("IsValidUPX returned true for data without UPX! magic")
			}
			if err != nil {
				t.Error("IsValidUPX returned error for data without UPX! magic")
			}
		}

		_ = valid
		_ = err
	})
}
