package action

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/cavaliergopher/cpio"
	"github.com/cavaliergopher/rpm"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"

	"github.com/egibs/go-debian/deb"

	"github.com/ulikunitz/xz"
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

// extractTar extracts .apk and .tar* archives.
func extractTar(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting tar")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	filename := filepath.Base(f)
	tf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()
	// Set offset to the file origin regardless of type
	_, err = tf.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	var tr *tar.Reader

	switch {
	case strings.Contains(f, ".apk") || strings.Contains(f, ".tar.gz") || strings.Contains(f, ".tgz"):
		gzStream, err := gzip.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzStream.Close()
		tr = tar.NewReader(gzStream)
	case strings.Contains(filename, ".tar.xz"):
		xzStream, err := xz.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		tr = tar.NewReader(xzStream)
	case strings.Contains(filename, ".xz"):
		xzStream, err := xz.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		uncompressed := strings.Trim(filepath.Base(f), ".xz")
		target := filepath.Join(d, uncompressed)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("failed to create directory for file: %w", err)
		}

		// #nosec G115 // ignore Type conversion which leads to integer overflow
		// header.Mode is int64 and FileMode is uint32
		f, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		defer f.Close()
		if _, err = io.Copy(f, xzStream); err != nil {
			return fmt.Errorf("failed to write decompressed xz output: %w", err)
		}
		return nil
	case strings.Contains(filename, ".tar.bz2") || strings.Contains(filename, ".tbz"):
		br := bzip2.NewReader(tf)
		tr = tar.NewReader(br)
	default:
		tr = tar.NewReader(tf)
	}

	for {
		header, err := tr.Next()

		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		clean := filepath.Clean(header.Name)
		if filepath.IsAbs(clean) || strings.Contains(clean, "../") {
			return fmt.Errorf("path is absolute or contains a relative path traversal: %s", clean)
		}

		target := filepath.Join(d, clean)
		if !isValidPath(target, d) {
			return fmt.Errorf("invalid file path: %s", target)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// #nosec G115 // ignore Type conversion which leads to integer overflow
			// header.Mode is int64 and FileMode is uint32
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			// #nosec G115 // ignore Type conversion which leads to integer overflow
			// header.Mode is int64 and FileMode is uint32
			out, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(out, io.LimitReader(tr, maxBytes)); err != nil {
				out.Close()
				return fmt.Errorf("failed to copy file: %w", err)
			}

			if err := out.Close(); err != nil {
				return fmt.Errorf("failed to close file: %w", err)
			}
		case tar.TypeSymlink:
			// Skip symlinks for targets that do not exist
			_, err = os.Readlink(target)
			if os.IsNotExist(err) {
				continue
			}
			// Ensure that symlinks are not relative path traversals
			// #nosec G305 // L208 handles the check
			linkReal, err := filepath.EvalSymlinks(filepath.Join(d, header.Linkname))
			if err != nil {
				return fmt.Errorf("failed to evaluate symlink: %w", err)
			}
			if !isValidPath(target, d) {
				return fmt.Errorf("symlink points outside temporary directory: %s", linkReal)
			}
			if err := os.Symlink(linkReal, target); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		}
	}
	return nil
}

// extractGzip extracts .gz archives.
func extractGzip(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	gf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer gf.Close()

	// Determine if we're extracting a gzip- or zlib-compressed file
	ft, err := programkind.File(f)
	if err != nil {
		return fmt.Errorf("failed to determine file type: %w", err)
	}

	logger.Debugf("extracting %s", ft.Ext)

	base := filepath.Base(f)
	target := filepath.Join(d, base[:len(base)-len(filepath.Ext(base))])

	switch ft.Ext {
	case "gzip":
		gr, err := gzip.NewReader(gf)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gr.Close()

		ef, err := os.Create(target)
		if err != nil {
			return fmt.Errorf("failed to create extracted file: %w", err)
		}
		defer ef.Close()

		if _, err := io.Copy(ef, io.LimitReader(gr, maxBytes)); err != nil {
			return fmt.Errorf("failed to copy file: %w", err)
		}
	case "Z":
		zr, err := zlib.NewReader(gf)
		if err != nil {
			return fmt.Errorf("failed to create zlib reader: %w", err)
		}
		defer zr.Close()

		ef, err := os.Create(target)
		if err != nil {
			return fmt.Errorf("failed to create extracted file: %w", err)
		}
		defer ef.Close()

		if _, err := io.Copy(ef, io.LimitReader(zr, maxBytes)); err != nil {
			return fmt.Errorf("failed to copy file: %w", err)
		}
	}

	return nil
}

// extractZip extracts .jar and .zip archives.
func extractZip(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting zip")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", f, err)
	}

	read, err := zip.OpenReader(f)
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", f, err)
	}
	defer read.Close()

	for _, file := range read.File {
		clean := filepath.Clean(filepath.ToSlash(file.Name))
		if strings.Contains(clean, "..") {
			logger.Warnf("skipping potentially unsafe file path: %s", file.Name)
			continue
		}

		name := filepath.Join(d, clean)
		if !isValidPath(name, d) {
			logger.Warnf("skipping file path outside extraction directory: %s", name)
			continue
		}

		// Check if a directory with the same name exists
		if info, err := os.Stat(name); err == nil && info.IsDir() {
			continue
		}

		if file.Mode().IsDir() {
			mode := file.Mode() | 0o700
			err := os.MkdirAll(name, mode)
			if err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		open, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		err = os.MkdirAll(filepath.Dir(name), 0o700)
		if err != nil {
			open.Close()
			return fmt.Errorf("failed to create directory: %w", err)
		}

		mode := file.Mode() | 0o200
		create, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			open.Close()
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err = io.Copy(create, io.LimitReader(open, maxBytes)); err != nil {
			open.Close()
			create.Close()
			return fmt.Errorf("failed to copy file: %w", err)
		}

		open.Close()
		create.Close()
	}
	return nil
}

// extractRPM extracts .rpm packages.
func extractRPM(ctx context.Context, d, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting rpm")

	rpmFile, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open RPM file: %w", err)
	}
	defer rpmFile.Close()

	pkg, err := rpm.Read(rpmFile)
	if err != nil {
		return fmt.Errorf("failed to read RPM package headers: %w", err)
	}

	if format := pkg.PayloadFormat(); format != "cpio" {
		return fmt.Errorf("unsupported payload format: %s", format)
	}

	payloadOffset, err := rpmFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to get payload offset: %w", err)
	}

	if _, err := rpmFile.Seek(payloadOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to payload: %w", err)
	}

	var cr *cpio.Reader
	switch compression := pkg.PayloadCompression(); compression {
	case "gzip":
		gzStream, err := gzip.NewReader(rpmFile)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzStream.Close()
		cr = cpio.NewReader(gzStream)
	case "xz":
		xzStream, err := xz.NewReader(rpmFile)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		cr = cpio.NewReader(xzStream)
	default:
		return fmt.Errorf("unsupported compression format: %s", compression)
	}

	for {
		header, err := cr.Next()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read cpio header: %w", err)
		}

		clean := filepath.Clean(header.Name)
		if filepath.IsAbs(clean) || strings.Contains(clean, "../") {
			return fmt.Errorf("path is absolute or contains a relative path traversal: %s", clean)
		}

		target := filepath.Join(d, clean)

		if header.FileInfo().IsDir() {
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("failed to create parent directory: %w", err)
		}

		out, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err := io.Copy(out, io.LimitReader(cr, maxBytes)); err != nil {
			out.Close()
			return fmt.Errorf("failed to copy file: %w", err)
		}

		if err := out.Close(); err != nil {
			return fmt.Errorf("failed to close file: %w", err)
		}
	}

	return nil
}

// extractDeb extracts .deb packages.
func extractDeb(ctx context.Context, d, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting deb")

	fd, err := os.Open(f)
	if err != nil {
		panic(err)
	}
	defer fd.Close()

	df, err := deb.Load(fd, f)
	if err != nil {
		panic(err)
	}
	defer df.Close()

	for {
		header, err := df.Data.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		clean := filepath.Clean(header.Name)
		if filepath.IsAbs(clean) || strings.Contains(clean, "../") {
			return fmt.Errorf("path is absolute or contains a relative path traversal: %s", clean)
		}

		target := filepath.Join(d, clean)

		switch header.Typeflag {
		case tar.TypeDir:
			// #nosec G115 // ignore Type conversion which leads to integer overflow
			// header.Mode is int64 and FileMode is uint32
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			// #nosec G115
			out, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(out, io.LimitReader(df.Data, maxBytes)); err != nil {
				out.Close()
				return fmt.Errorf("failed to copy file: %w", err)
			}

			if err := out.Close(); err != nil {
				return fmt.Errorf("failed to close file: %w", err)
			}
		case tar.TypeSymlink:
			// Skip symlinks for targets that do not exist
			_, err = os.Readlink(target)
			if os.IsNotExist(err) {
				continue
			}
			// Ensure that symlinks are not relative path traversals
			// #nosec G305 // L208 handles the check
			linkReal, err := filepath.EvalSymlinks(filepath.Join(d, header.Linkname))
			if err != nil {
				return fmt.Errorf("failed to evaluate symlink: %w", err)
			}
			if !isValidPath(linkReal, d) {
				return fmt.Errorf("symlink points outside temporary directory: %s", linkReal)
			}
			if err := os.Symlink(linkReal, target); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		}
	}

	return nil
}

func extractBz2(ctx context.Context, d, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting bzip2 file")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	tf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()
	// Set offset to the file origin regardless of type
	_, err = tf.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	br := bzip2.NewReader(tf)
	uncompressed := strings.TrimSuffix(filepath.Base(f), ".bz2")
	uncompressed = strings.TrimSuffix(uncompressed, ".bzip2")
	target := filepath.Join(d, uncompressed)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return fmt.Errorf("failed to create directory for file: %w", err)
	}

	// #nosec G115 // ignore Type conversion which leads to integer overflow
	// header.Mode is int64 and FileMode is uint32
	out, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, io.LimitReader(br, maxBytes)); err != nil {
		out.Close()
		return fmt.Errorf("failed to copy file: %w", err)
	}
	return nil
}

func extractNestedArchive(
	ctx context.Context,
	d string,
	f string,
	extracted *sync.Map,
) error {
	isArchive := false
	ext := getExt(f)
	if _, ok := archiveMap[ext]; ok {
		isArchive = true
	}
	//nolint:nestif // ignore complexity of 8
	if isArchive {
		// Ensure the file was extracted and exists
		fullPath := filepath.Join(d, f)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %w", err)
		}
		extract := extractionMethod(ext)
		if extract == nil {
			return fmt.Errorf("unsupported archive type: %s", ext)
		}

		err := extract(ctx, d, fullPath)
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

	ext := getExt(path)
	extract := extractionMethod(ext)
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
