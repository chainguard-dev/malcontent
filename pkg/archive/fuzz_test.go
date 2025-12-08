package archive

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// FuzzExtractTar tests tar extraction with random inputs to find crashes,
// path traversal vulnerabilities, and other issues.
func FuzzExtractTar(f *testing.F) {
	testdata := []string{
		"../../pkg/action/testdata/apko.tar.gz",
		"../../pkg/action/testdata/apko_nested.tar.gz",
	}

	for _, td := range testdata {
		if data, err := os.ReadFile(td); err == nil {
			f.Add(data)
		}
	}

	f.Add([]byte{}) // empty file
	f.Add([]byte("not a tar file"))
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}) // gzip magic bytes only

	f.Fuzz(func(t *testing.T, data []byte) {
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		"../../pkg/action/testdata/apko.zip",
		"../../pkg/action/testdata/conflict.zip",
		"../../pkg/action/testdata/17419.zip",
	}

	for _, td := range testdata {
		if data, err := os.ReadFile(td); err == nil {
			f.Add(data)
		}
	}

	f.Add([]byte{})                       // empty file
	f.Add([]byte("PK"))                   // zip magic bytes only
	f.Add([]byte{0x50, 0x4b, 0x03, 0x04}) // full zip signature

	f.Fuzz(func(t *testing.T, data []byte) {
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		"../../pkg/action/testdata/apko.tar.gz",
		"../../pkg/action/testdata/apko_nested.tar.gz",
		"../../pkg/action/testdata/apko.zip",
		"../../pkg/action/testdata/apko.gz",
	}

	for _, td := range testdata {
		if data, err := os.ReadFile(td); err == nil {
			switch {
			case strings.HasSuffix(td, ".tar.gz"):
				f.Add(data, ".tar.gz")
			case strings.HasSuffix(td, ".zip"):
				f.Add(data, ".zip")
			case strings.HasSuffix(td, ".gz"):
				f.Add(data, ".gz")
			}
		}
	}

	f.Add([]byte{}, ".tar.gz")                       // empty file
	f.Add([]byte("not a tar file"), ".tar.gz")       // invalid content
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}, ".tar.gz") // gzip magic bytes only
	f.Add([]byte{0x50, 0x4b, 0x03, 0x04}, ".zip")    // zip magic bytes
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}, ".gz")     // gzip header

	f.Fuzz(func(t *testing.T, data []byte, ext string) {
		if ext != ".tar.gz" && ext != ".zip" && ext != ".gz" && ext != ".tar" {
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
