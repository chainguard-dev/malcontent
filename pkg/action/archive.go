package action

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

var archiveMap = map[string]bool{
	".apk":    true,
	".bz2":    true,
	".bzip2":  true,
	".deb":    true,
	".gem":    true,
	".gz":     true,
	".jar":    true,
	".rpm":    true,
	".tar":    true,
	".tar.gz": true,
	".tar.xz": true,
	".tgz":    true,
	".whl":    true,
	".xz":     true,
	".zip":    true,
}

// isSupportedArchive returns whether a path can be processed by our archive extractor.
func isSupportedArchive(path string) bool {
	return archiveMap[getExt(path)]
}

// isValidPath checks if the target file is within the given directory.
func isValidPath(target, dir string) bool {
	return strings.HasPrefix(filepath.Clean(target), filepath.Clean(dir))
}

// getExt returns the extension of a file path
// and attempts to avoid including fragments of filenames with other dots before the extension.
func getExt(path string) string {
	base := filepath.Base(path)

	// Handle files with version numbers in the name
	// e.g. file1.2.3.tar.gz -> .tar.gz
	re := regexp.MustCompile(`\d+\.\d+\.\d+$`)
	base = re.ReplaceAllString(base, "")

	ext := filepath.Ext(base)

	if ext != "" && strings.Contains(base, ".") {
		parts := strings.Split(base, ".")
		if len(parts) > 2 {
			subExt := fmt.Sprintf(".%s%s", parts[len(parts)-2], ext)
			if isValidExt := func(ext string) bool {
				_, ok := archiveMap[ext]
				return ok
			}(subExt); isValidExt {
				return subExt
			}
		}
	}

	return ext
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
	if _, ok := archiveMap[getExt(f)]; ok {
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
			extract = extractZlib
		} else {
			extract = extractionMethod(getExt(fullPath))
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
func extractArchiveToTempDir(ctx context.Context, path string) (string, error) {
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
		extract = extractZlib
	} else {
		extract = extractionMethod(getExt(path))
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
			ext := getExt(file)
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
				if _, ok := archiveMap[ext]; ok {
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

func extractionMethod(ext string) func(context.Context, string, string) error {
	switch ext {
	case ".jar", ".zip", ".whl":
		return extractZip
	case ".gz":
		return extractGzip
	case ".apk", ".gem", ".tar", ".tar.bz2", ".tar.gz", ".tgz", ".tar.xz", ".tbz", ".xz":
		return extractTar
	case ".bz2", ".bzip2":
		return extractBz2
	case ".rpm":
		return extractRPM
	case ".deb":
		return extractDeb
	default:
		return nil
	}
}
