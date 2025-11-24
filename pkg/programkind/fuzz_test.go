package programkind

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FuzzFile tests file type detection with random inputs.
func FuzzFile(f *testing.F) {
	samplesDir := "../../out/chainguard-dev/malcontent-samples"
	err := filepath.WalkDir(samplesDir, func(path string, d os.DirEntry, _ error) error {
		if d == nil || d.IsDir() {
			return nil
		}
		if filepath.Base(path)[0] == '.' {
			return nil
		}

		if data, readErr := os.ReadFile(path); readErr == nil {
			if len(data) <= 10*1024*1024 { // 10MB max
				f.Add(data, filepath.Base(path))
			}
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

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, ft, err := File(ctx, tmpFile.Name())

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
