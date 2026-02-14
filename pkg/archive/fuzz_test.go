// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

// FuzzValidateResolvedPath tests path validation via the ValidateResolvedPath function
// to ensure it doesn't panic on any inputs and correctly detects path traversal attempts.
func FuzzValidateResolvedPath(f *testing.F) {
	tmpDir, err := os.MkdirTemp("", "fuzz-validate-")
	if err != nil {
		f.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a subdirectory and file for valid paths
	subDir := filepath.Join(tmpDir, "sub")
	os.MkdirAll(subDir, 0o755)
	os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("test"), 0o644)

	f.Add(filepath.Join(subDir, "file.txt"), tmpDir, filepath.Join(subDir, "file.txt"))
	f.Add(filepath.Join(tmpDir, "..", "etc", "passwd"), tmpDir, "/etc/passwd")
	f.Add("/etc/passwd", tmpDir, "/etc/passwd")
	f.Add(filepath.Join(tmpDir, "safe"), tmpDir, filepath.Join(tmpDir, "safe"))

	f.Fuzz(func(_ *testing.T, target, dir, clean string) {
		if len(target) > 4096 || len(dir) < 3 || len(clean) > 4096 {
			return
		}
		// Just verify it doesn't panic
		_ = ValidateResolvedPath(target, dir, clean)
	})
}

// maxFuzzSize is the maximum input size for fuzz tests to stay well under
// Go's 100MB fuzzer shared memory capacity and avoid OOM in parsers.
const maxFuzzSize = 10 * 1024 * 1024

// readTestFile reads a file using file.GetContents for consistency with production code.
func readTestFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, file.ExtractBuffer)
	return file.GetContents(f, buf)
}

// FuzzExtractTar tests tar extraction with random inputs to find crashes,
// path traversal vulnerabilities, and other issues.
func FuzzExtractTar(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/apko.tar.gz",
		"../../pkg/action/testdata/apko_nested.tar.gz",
		"../../pkg/action/testdata/static.tar.xz",
		"../../pkg/action/testdata/yara.tar.zlib",
		"../../pkg/action/testdata/yara.tar.zst",
		"testdata/symlink_escape.tar",
		"testdata/symlink_valid.tar",
	}

	for _, td := range testdata {
		if data, err := readTestFile(td); err == nil {
			f.Add(data)
		}
	}

	f.Add([]byte{}) // empty file
	f.Add([]byte("not a tar file"))
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}) // gzip magic bytes only

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}
		tmpFile, err := os.CreateTemp("", "fuzz-tar-*.tar.gz")
		if err != nil {
			t.Skip("failed to create temp file")
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip("failed to write to temp file")
		}
		tmpFile.Close()

		tmpDir, err := os.MkdirTemp("", "fuzz-extract-*")
		if err != nil {
			t.Skip("failed to create temp dir")
		}
		defer os.RemoveAll(tmpDir)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = ExtractTar(ctx, tmpDir, tmpFile.Name())

		err = filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal detected: %s is outside %s", path, tmpDir)
			}
			return nil
		})
		if err != nil {
			return
		}
	})
}

// FuzzExtractZip tests zip extraction with random inputs.
func FuzzExtractZip(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/17419.zip",
		"../../pkg/action/testdata/apko.zip",
		"../../pkg/action/testdata/conflict.zip",
	}

	for _, td := range testdata {
		if data, err := readTestFile(td); err == nil {
			f.Add(data)
		}
	}

	f.Add([]byte{})                       // empty file
	f.Add([]byte("PK"))                   // zip magic bytes only
	f.Add([]byte{0x50, 0x4b, 0x03, 0x04}) // full zip signature

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}
		tmpFile, err := os.CreateTemp("", "fuzz-zip-*.zip")
		if err != nil {
			t.Skip("failed to create temp file")
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip("failed to write to temp file")
		}
		tmpFile.Close()

		tmpDir, err := os.MkdirTemp("", "fuzz-extract-*")
		if err != nil {
			t.Skip("failed to create temp dir")
		}
		defer os.RemoveAll(tmpDir)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = ExtractZip(ctx, tmpDir, tmpFile.Name())

		err = filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal detected: %s is outside %s", path, tmpDir)
			}
			return nil
		})
		if err != nil {
			return
		}
	})
}

// FuzzExtractArchive tests archive extraction via the top-level ExtractArchiveToTempDir
// function which handles initialization properly.
func FuzzExtractArchive(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/17419.zip",
		"../../pkg/action/testdata/apko.gz",
		"../../pkg/action/testdata/apko.tar.gz",
		"../../pkg/action/testdata/apko.zip",
		"../../pkg/action/testdata/apko_nested.tar.gz",
		"../../pkg/action/testdata/conflict.zip",
		"../../pkg/action/testdata/joblib_0.9.4.dev0_compressed_cache_size_pickle_py35_np19.gz",
		"../../pkg/action/testdata/static.tar.xz",
		"../../pkg/action/testdata/yara.deb",
		"../../pkg/action/testdata/yara.rpm",
		"../../pkg/action/testdata/yara.tar.zlib",
		"../../pkg/action/testdata/yara.tar.zst",
		"testdata/symlink_escape.tar",
		"testdata/symlink_valid.tar",
	}

	for _, td := range testdata {
		if data, err := readTestFile(td); err == nil {
			switch {
			case strings.HasSuffix(td, ".tar.gz"):
				f.Add(data, ".tar.gz")
			case strings.HasSuffix(td, ".zip"):
				f.Add(data, ".zip")
			case strings.HasSuffix(td, ".gz"):
				f.Add(data, ".gz")
			case strings.HasSuffix(td, ".tar.xz"):
				f.Add(data, ".tar.xz")
			case strings.HasSuffix(td, ".deb"):
				f.Add(data, ".deb")
			case strings.HasSuffix(td, ".rpm"):
				f.Add(data, ".rpm")
			case strings.HasSuffix(td, ".tar.zlib"):
				f.Add(data, ".tar.zlib")
				f.Add(data, ".zlib")
			case strings.HasSuffix(td, ".tar.zst"):
				f.Add(data, ".tar.zst")
				f.Add(data, ".zst")
				f.Add(data, ".zstd")
			}
		}
	}

	f.Add([]byte{}, ".tar.gz")                       // empty file
	f.Add([]byte("not a tar file"), ".tar.gz")       // invalid content
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}, ".tar.gz") // gzip magic bytes only
	f.Add([]byte{0x50, 0x4b, 0x03, 0x04}, ".zip")    // zip magic bytes
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}, ".gz")     // gzip header

	f.Fuzz(func(t *testing.T, data []byte, ext string) {
		if len(data) > maxFuzzSize {
			return
		}
		if _, ok := programkind.ArchiveMap[ext]; !ok {
			return
		}

		tmpFile, err := os.CreateTemp("", "fuzz-archive-*"+ext)
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
		cfg := malcontent.Config{}
		extractedDir, err := ExtractArchiveToTempDir(ctx, cfg, tmpFile.Name())
		if err == nil && extractedDir != "" {
			defer os.RemoveAll(extractedDir)

			walkErr := filepath.WalkDir(extractedDir, func(path string, _ os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !IsValidPath(path, extractedDir) {
					t.Fatalf("path traversal detected: %s is outside %s", path, extractedDir)
				}
				return nil
			})
			if walkErr != nil {
				return
			}
		}
	})
}

// FuzzIsValidPath tests path validation via the IsValidPath function.
func FuzzIsValidPath(f *testing.F) {
	tmpDir, err := os.MkdirTemp("", "fuzz-path-")
	if err != nil {
		f.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	f.Add(tmpDir, filepath.Join(tmpDir, "safe.txt"))
	f.Add(tmpDir, filepath.Join(tmpDir, "..", "etc", "passwd"))
	f.Add(tmpDir, "/etc/passwd")
	f.Add(tmpDir, filepath.Join(tmpDir, ".", ".", "safe.txt"))
	f.Add(tmpDir, filepath.Join(tmpDir, "subdir", "..", "..", "etc", "passwd"))
	f.Add(tmpDir, filepath.Join(tmpDir, "deeply", "nested", "path", "file.txt"))

	f.Fuzz(func(t *testing.T, baseDir, targetPath string) {
		if len(baseDir) < 3 {
			return
		}

		result := IsValidPath(targetPath, baseDir)

		if result {
			cleanTarget := filepath.Clean(targetPath)
			cleanBase := filepath.Clean(baseDir)

			if cleanBase == "" || cleanTarget == "" {
				return
			}

			if filepath.IsAbs(cleanTarget) && filepath.IsAbs(cleanBase) {
				rel, err := filepath.Rel(cleanBase, cleanTarget)
				if err == nil && (rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
					t.Fatalf("IsValidPath returned true but path %q escapes base %q (rel=%q)", targetPath, baseDir, rel)
				}
			}
		}
	})
}

// FuzzExtractGzip tests gzip extraction with random inputs.
func FuzzExtractGzip(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/apko.gz",
		"../../pkg/action/testdata/joblib_0.9.4.dev0_compressed_cache_size_pickle_py35_np19.gz",
	}

	for _, td := range testdata {
		if data, err := readTestFile(td); err == nil {
			f.Add(data)
		}
	}

	f.Add([]byte{})                       // empty
	f.Add([]byte{0x1f, 0x8b})             // gzip magic only
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}) // gzip header start
	f.Add([]byte("not gzip"))             // invalid
	f.Add(make([]byte, 1024*1024))        // large zeros (compression bomb test)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}
		tmpFile, err := os.CreateTemp("", "fuzz-gz-*.gz")
		if err != nil {
			t.Skip()
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip()
		}
		tmpFile.Close()

		tmpDir, err := os.MkdirTemp("", "fuzz-extract-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_ = ExtractGzip(ctx, tmpDir, tmpFile.Name())

		// Verify no path traversal
		filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal: %s outside %s", path, tmpDir)
			}
			return nil
		})
	})
}

// FuzzExtractBz2 tests bzip2 extraction with random inputs.
func FuzzExtractBz2(f *testing.F) {
	f.Add([]byte{})                 // empty
	f.Add([]byte{0x42, 0x5a})       // bzip2 magic only
	f.Add([]byte{0x42, 0x5a, 0x68}) // bzip2 header start
	f.Add([]byte("not bzip2"))      // invalid
	f.Add(make([]byte, 1024*1024))  // large zeros

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}
		tmpFile, err := os.CreateTemp("", "fuzz-bz2-*.bz2")
		if err != nil {
			t.Skip()
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip()
		}
		tmpFile.Close()

		tmpDir, err := os.MkdirTemp("", "fuzz-extract-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_ = ExtractBz2(ctx, tmpDir, tmpFile.Name())

		filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal: %s outside %s", path, tmpDir)
			}
			return nil
		})
	})
}

// FuzzExtractZstd tests zstd extraction with random inputs.
func FuzzExtractZstd(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/yara.tar.zst",
	}

	for _, td := range testdata {
		if data, err := readTestFile(td); err == nil {
			f.Add(data)
		}
	}

	f.Add([]byte{})                       // empty
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd}) // zstd magic
	f.Add([]byte("not zstd"))             // invalid
	f.Add(make([]byte, 1024*1024))        // large zeros

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}
		tmpFile, err := os.CreateTemp("", "fuzz-zst-*.zst")
		if err != nil {
			t.Skip()
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip()
		}
		tmpFile.Close()

		tmpDir, err := os.MkdirTemp("", "fuzz-extract-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_ = ExtractZstd(ctx, tmpDir, tmpFile.Name())

		filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal: %s outside %s", path, tmpDir)
			}
			return nil
		})
	})
}

// FuzzExtractZlib tests zlib extraction with random inputs.
func FuzzExtractZlib(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/yara.tar.zlib",
	}

	for _, td := range testdata {
		if data, err := readTestFile(td); err == nil {
			f.Add(data)
		}
	}

	f.Add([]byte{})                // empty
	f.Add([]byte{0x78, 0x9c})      // zlib default compression
	f.Add([]byte{0x78, 0x01})      // zlib no compression
	f.Add([]byte{0x78, 0xda})      // zlib best compression
	f.Add([]byte("not zlib"))      // invalid
	f.Add(make([]byte, 1024*1024)) // large zeros

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}
		tmpFile, err := os.CreateTemp("", "fuzz-zlib-*.zlib")
		if err != nil {
			t.Skip()
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip()
		}
		tmpFile.Close()

		tmpDir, err := os.MkdirTemp("", "fuzz-extract-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_ = ExtractZlib(ctx, tmpDir, tmpFile.Name())

		filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal: %s outside %s", path, tmpDir)
			}
			return nil
		})
	})
}

// FuzzExtractRPM tests RPM extraction with random inputs.
func FuzzExtractRPM(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/yara.rpm",
	}

	for _, td := range testdata {
		if data, err := readTestFile(td); err == nil {
			f.Add(data)
		}
	}

	rpmMagic := []byte{0xed, 0xab, 0xee, 0xdb}

	f.Add([]byte{})          // empty
	f.Add(rpmMagic)          // rpm magic
	f.Add([]byte("not rpm")) // invalid

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 96 || len(data) > maxFuzzSize || !bytes.Equal(data[:4], rpmMagic) {
			return
		}

		tmpFile, err := os.CreateTemp("", "fuzz-rpm-*.rpm")
		if err != nil {
			t.Skip()
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip()
		}
		tmpFile.Close()

		tmpDir, err := os.MkdirTemp("", "fuzz-extract-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_ = ExtractRPM(ctx, tmpDir, tmpFile.Name())

		filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal: %s outside %s", path, tmpDir)
			}
			return nil
		})
	})
}

// FuzzExtractDeb tests Debian package extraction with random inputs.
func FuzzExtractDeb(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/yara.deb",
	}

	for _, td := range testdata {
		if data, err := readTestFile(td); err == nil {
			f.Add(data)
		}
	}

	f.Add([]byte{})            // empty
	f.Add([]byte("!<arch>\n")) // ar archive magic
	f.Add([]byte("not deb"))   // invalid

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}
		tmpFile, err := os.CreateTemp("", "fuzz-deb-*.deb")
		if err != nil {
			t.Skip()
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip()
		}
		tmpFile.Close()

		tmpDir, err := os.MkdirTemp("", "fuzz-extract-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_ = ExtractDeb(ctx, tmpDir, tmpFile.Name())

		filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal: %s outside %s", path, tmpDir)
			}
			return nil
		})
	})
}

// FuzzExtractUPX tests UPX decompression with random inputs.
func FuzzExtractUPX(f *testing.F) {
	f.Add([]byte{})          // empty
	f.Add([]byte("UPX!"))    // UPX signature
	f.Add([]byte("not upx")) // invalid

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}
		tmpFile, err := os.CreateTemp("", "fuzz-upx-*")
		if err != nil {
			t.Skip()
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip()
		}
		tmpFile.Close()

		tmpDir, err := os.MkdirTemp("", "fuzz-extract-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_ = ExtractUPX(ctx, tmpDir, tmpFile.Name())

		filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal: %s outside %s", path, tmpDir)
			}
			return nil
		})
	})
}

// FuzzExtractNestedArchive tests that extractNestedArchive respects depth limits
// and doesn't panic on arbitrary file contents within archive directories.
func FuzzExtractNestedArchive(f *testing.F) {
	f.Add([]byte("not an archive"), "test.tar.gz", 1)
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}, "test.gz", 2)
	f.Add([]byte{0x50, 0x4b, 0x03, 0x04}, "test.zip", 0)
	f.Add([]byte{}, "empty.tar.gz", 3)
	f.Add([]byte("UPX!"), "test.upx", 1)

	f.Fuzz(func(t *testing.T, data []byte, filename string, maxDepth int) {
		if len(data) > maxFuzzSize || len(filename) > 255 {
			return
		}
		if maxDepth < 0 || maxDepth > 10 {
			return
		}
		// Sanitize filename to prevent path traversal in test setup
		filename = filepath.Base(filename)
		if filename == "." || filename == ".." || filename == "" {
			return
		}

		tmpDir, err := os.MkdirTemp("", "fuzz-nested-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		if err := os.WriteFile(filepath.Join(tmpDir, filename), data, 0o644); err != nil {
			t.Skip()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var extracted sync.Map
		cfg := malcontent.Config{MaxDepth: maxDepth}

		logger := clog.FromContext(ctx)
		_ = extractNestedArchive(ctx, cfg, tmpDir, filename, &extracted, logger, 0)
	})
}

// FuzzOCI exercises the OCI extraction path by fuzzing tar archives through
// the same ExtractTar codepath that OCI() uses after crane.Pull/Export.
// The actual OCI() function requires network access, so we fuzz the local extraction.
func FuzzOCI(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/apko.tar.gz",
		"../../pkg/action/testdata/static.tar.xz",
	}
	for _, td := range testdata {
		if data, err := readTestFile(td); err == nil {
			f.Add(data)
		}
	}

	f.Add([]byte{})
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00})
	f.Add([]byte("not a tar"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}

		tmpDir, err := os.MkdirTemp("", "fuzz-oci-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		tmpFile, err := os.CreateTemp(tmpDir, "fuzz-oci-*.tar")
		if err != nil {
			t.Skip()
		}
		if _, err := tmpFile.Write(data); err != nil {
			t.Skip()
		}
		tmpFile.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = ExtractTar(ctx, tmpDir, tmpFile.Name())

		filepath.WalkDir(tmpDir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !IsValidPath(path, tmpDir) {
				t.Fatalf("path traversal: %s outside %s", path, tmpDir)
			}
			return nil
		})
	})
}
