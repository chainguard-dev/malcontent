package archive

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

// isValidPath checks if the target file is within the given directory.
func IsValidPath(target, dir string) bool {
	return strings.HasPrefix(filepath.Clean(target), filepath.Clean(dir))
}

const maxBytes = 1 << 29 // 512MB

func extractNestedArchive(
	ctx context.Context,
	d string,
	f string,
	extracted *sync.Map,
) error {
	isArchive := false
	// zlib-compressed files are also archives
	ft, err := programkind.File(f)
	if err != nil {
		return fmt.Errorf("failed to determine file type: %w", err)
	}
	if ft != nil && ft.MIME == "application/zlib" {
		isArchive = true
	}
	if _, ok := programkind.ArchiveMap[programkind.GetExt(f)]; ok {
		isArchive = true
	}
	//nolint:nestif // ignore complexity of 8
	if isArchive {
		// Ensure the file was extracted and exists
		fullPath := filepath.Join(d, f)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %w", err)
		}

		var extract func(context.Context, string, string) error
		// Check for zlib-compressed files first and use the zlib-specific function
		ft, err := programkind.File(fullPath)
		if err != nil {
			return fmt.Errorf("failed to determine file type: %w", err)
		}
		if ft != nil && ft.MIME == "application/zlib" {
			extract = ExtractZlib
		} else {
			extract = ExtractionMethod(programkind.GetExt(fullPath))
		}
		err = extract(ctx, d, fullPath)
		if err != nil {
			return fmt.Errorf("extract nested archive: %w", err)
		}
		// Mark the file as extracted
		extracted.Store(f, true)

		// Remove the nested archive file
		// This is done to prevent the file from being scanned
		if err := os.Remove(fullPath); err != nil {
			return fmt.Errorf("failed to remove file: %w", err)
		}

		// Check if there are any newly extracted files that are also archives
		files, err := os.ReadDir(d)
		if err != nil {
			return fmt.Errorf("failed to read directory after extraction: %w", err)
		}
		for _, file := range files {
			relPath := filepath.Join(d, file.Name())
			if _, isExtracted := extracted.Load(relPath); !isExtracted {
				if err := extractNestedArchive(ctx, d, file.Name(), extracted); err != nil {
					return fmt.Errorf("failed to extract nested archive %s: %w", file.Name(), err)
				}
			}
		}
	}
	return nil
}

// extractArchiveToTempDir creates a temporary directory and extracts the archive file for scanning.
func ExtractArchiveToTempDir(ctx context.Context, path string) (string, error) {
	logger := clog.FromContext(ctx).With("path", path)
	logger.Debug("creating temp dir")

	tmpDir, err := os.MkdirTemp("", filepath.Base(path))
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	var extract func(context.Context, string, string) error
	// Check for zlib-compressed files first and use the zlib-specific function
	ft, err := programkind.File(path)
	if err != nil {
		return "", fmt.Errorf("failed to determine file type: %w", err)
	}
	if ft != nil && ft.MIME == "application/zlib" {
		extract = ExtractZlib
	} else {
		extract = ExtractionMethod(programkind.GetExt(path))
	}
	if extract == nil {
		return "", fmt.Errorf("unsupported archive type: %s", path)
	}
	err = extract(ctx, tmpDir, path)
	if err != nil {
		return "", fmt.Errorf("failed to extract %s: %w", path, err)
	}

	var extractedFiles sync.Map
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		return "", fmt.Errorf("failed to read files in directory %s: %w", tmpDir, err)
	}
	for _, file := range files {
		extractedFiles.Store(filepath.Join(tmpDir, file.Name()), false)
	}

	extractedFiles.Range(func(key, _ any) bool {
		if key == nil {
			return true
		}
		//nolint: nestif // ignoring complexity of 11
		if file, ok := key.(string); ok {
			ext := programkind.GetExt(file)
			info, err := os.Stat(file)
			if err != nil {
				return false
			}
			switch mode := info.Mode(); {
			case mode.IsDir():
				err = filepath.WalkDir(file, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					rel, err := filepath.Rel(tmpDir, path)
					if err != nil {
						return fmt.Errorf("filepath.Rel: %w", err)
					}
					if !d.IsDir() {
						if err := extractNestedArchive(ctx, tmpDir, rel, &extractedFiles); err != nil {
							return fmt.Errorf("failed to extract nested archive %s: %w", rel, err)
						}
					}

					return nil
				})
				if err != nil {
					return false
				}
				return true
			case mode.IsRegular():
				if _, ok := programkind.ArchiveMap[ext]; ok {
					rel, err := filepath.Rel(tmpDir, file)
					if err != nil {
						return false
					}
					if err := extractNestedArchive(ctx, tmpDir, rel, &extractedFiles); err != nil {
						return false
					}
				}
				return true
			}
		}
		return true
	})

	return tmpDir, nil
}

func ExtractionMethod(ext string) func(context.Context, string, string) error {
	switch ext {
	case ".jar", ".zip", ".whl":
		return ExtractZip
	case ".apk", ".gem", ".tar", ".tar.bz2", ".tar.gz", ".tgz", ".tar.xz", ".tbz", ".xz":
		return ExtractTar
	case ".gz":
		return ExtractGzip
	case ".bz2", ".bzip2":
		return ExtractBz2
	case ".rpm":
		return ExtractRPM
	case ".deb":
		return ExtractDeb
	default:
		return nil
	}
}
