// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gabriel-vasile/mimetype"
)

// Supported archive extensions.
var ArchiveMap = map[string]bool{
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
	".upx":    true,
	".whl":    true,
	".xz":     true,
	".zst":    true,
	".zstd":   true,
	".zip":    true,
}

// file extension to MIME type, if it's a good scanning target.
var supportedKind = map[string]string{
	"7z":      "",
	"Z":       "application/zlib",
	"asm":     "",
	"bash":    "application/x-bsh",
	"bat":     "application/bat",
	"beam":    "application/x-erlang-binary",
	"bin":     "application/octet-stream",
	"c":       "text/x-c",
	"cc":      "text/x-c",
	"class":   "application/java-vm",
	"com":     "application/octet-stream",
	"cpp":     "text/x-c",
	"cron":    "text/x-cron",
	"crontab": "text/x-crontab",
	"csh":     "application/x-csh",
	"cxx":     "text/x-c",
	"dll":     "application/octet-stream",
	"dylib":   "application/x-sharedlib",
	"elf":     "application/x-elf",
	"exe":     "application/octet-stream",
	"expect":  "text/x-expect",
	"fish":    "text/x-fish",
	"go":      "text/x-go",
	"gzip":    "application/gzip",
	"h":       "text/x-h",
	"hh":      "text/x-h",
	"html":    "",
	"java":    "text/x-java",
	"js":      "application/javascript",
	"lnk":     "application/x-ms-shortcut",
	"lua":     "text/x-lua",
	"macho":   "application/x-mach-binary",
	"md":      "",
	"o":       "application/octet-stream",
	"php":     "text/x-php",
	"pl":      "text/x-perl",
	"pm":      "text/x-script.perl-module",
	"ps1":     "text/x-powershell",
	"py":      "text/x-python",
	"pyc":     "application/x-python-code",
	"rb":      "text/x-ruby",
	"rs":      "text/x-rust",
	"scpt":    "application/x-applescript",
	"scptd":   "application/x-applescript",
	"script":  "text/x-generic-script",
	"service": "text/x-systemd",
	"sh":      "application/x-sh",
	"so":      "application/x-sharedlib",
	"ts":      "application/typescript",
	"upx":     "application/x-upx",
	"whl":     "application/x-wheel+zip",
	"yaml":    "",
	"yara":    "",
	"yml":     "",
	"zsh":     "application/x-zsh",
}

type FileType struct {
	Ext  string
	MIME string
}

// IsSupportedArchive returns whether a path can be processed by our archive extractor.
// UPX files are an edge case since they may or may not even have an extension that can be referenced.
func IsSupportedArchive(path string) bool {
	if _, isValidArchive := ArchiveMap[GetExt(path)]; isValidArchive {
		return true
	}
	if ft, err := File(path); err == nil && ft != nil {
		if ft.MIME == "application/x-upx" {
			return true
		}
	}
	return false
}

// getExt returns the extension of a file path
// and attempts to avoid including fragments of filenames with other dots before the extension.
func GetExt(path string) string {
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
				_, ok := ArchiveMap[ext]
				return ok
			}(subExt); isValidExt {
				return subExt
			}
		}
	}

	return ext
}

var ErrUPXNotFound = errors.New("UPX executable not found in PATH")

func UPXInstalled() error {
	_, err := exec.LookPath("upx")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return ErrUPXNotFound
		}
		return fmt.Errorf("failed to check for UPX executable: %w", err)
	}
	return nil
}

// IsValidUPX checks whether a suspected UPX-compressed file can be decompressed with UPX.
func IsValidUPX(header []byte, path string) (bool, error) {
	if !bytes.Contains(header, []byte("UPX!")) {
		return false, nil
	}

	if err := UPXInstalled(); err != nil {
		return false, err
	}

	cmd := exec.Command("upx", "-l", "-f", path)
	output, err := cmd.CombinedOutput()

	if err != nil && (bytes.Contains(output, []byte("NotPackedException")) ||
		bytes.Contains(output, []byte("not packed by UPX"))) {
		return false, nil
	}

	return true, nil
}

func makeFileType(path string, ext string, mime string) *FileType {
	ext = strings.TrimPrefix(ext, ".")

	// the only JSON files we currently scan are NPM package metadata, which ends in *package.json
	if strings.HasSuffix(path, "package.json") {
		return &FileType{MIME: "application/json", Ext: ext}
	}

	if supportedKind[ext] == "" {
		return nil
	}

	// fix mimetype bug that defaults elf binaries to x-sharedlib
	if mime == "application/x-sharedlib" && !strings.Contains(path, ".so") {
		return Path(".elf")
	}

	if strings.Contains(mime, "application") || strings.Contains(mime, "text/x-") || strings.Contains(mime, "text/x-") || strings.Contains(mime, "executable") {
		return &FileType{MIME: mime, Ext: ext}
	}

	return nil
}

// File detects what kind of program this file might be.
//
//nolint:cyclop // ignore complexity of 38
func File(path string) (*FileType, error) {
	// Follow symlinks and return cleanly if the target does not exist
	_, err := filepath.EvalSymlinks(path)
	if os.IsNotExist(err) {
		return nil, nil
	}

	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	if st.IsDir() {
		return nil, nil
	}
	if st.Mode().Type() == fs.ModeIrregular {
		return nil, nil
	}

	// first strategy: mimetype
	mtype, err := mimetype.DetectFile(path)
	if err == nil {
		if ft := makeFileType(path, mtype.Extension(), mtype.String()); ft != nil {
			return ft, nil
		}
	}

	// second strategy: path (extension, mostly)
	if mtype := Path(path); mtype != nil {
		return mtype, nil
	}

	// read file header
	var hdr [256]byte
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	_, err = io.ReadFull(f, hdr[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read: %w", err)
	}

	// final strategy: DIY matching where mimetype is too strict.
	s := string(hdr[:])
	if isUPX, err := IsValidUPX(hdr[:], path); err == nil && isUPX {
		return Path(".upx"), nil
	}

	switch {
	case hdr[0] == '\x7f' && hdr[1] == 'E' || hdr[2] == 'L' || hdr[3] == 'F':
		return Path(".elf"), nil
	case strings.Contains(s, "<?php"):
		return Path(".php"), nil
	case strings.HasPrefix(s, "import "):
		return Path(".py"), nil
	case strings.Contains(s, " = require("):
		return Path(".js"), nil
	case strings.HasPrefix(s, "#!/bin/ash") ||
		strings.HasPrefix(s, "#!/bin/bash") ||
		strings.HasPrefix(s, "#!/bin/fish") ||
		strings.HasPrefix(s, "#!/bin/sh") ||
		strings.HasPrefix(s, "#!/bin/zsh") ||
		strings.Contains(s, `if [`) ||
		strings.Contains(s, "if !") ||
		strings.Contains(s, `echo "`) ||
		strings.Contains(s, `grep `) ||
		strings.Contains(s, "; then") ||
		strings.Contains(s, "export ") ||
		strings.HasSuffix(path, "profile"):
		return Path(".sh"), nil
	case strings.HasPrefix(s, "#!"):
		return Path(".script"), nil
	case strings.Contains(s, "#include <"):
		return Path(".c"), nil
	case strings.Contains(s, "BEAMAtU8"):
		return Path(".beam"), nil
	case hdr[0] == '\x1f' && hdr[1] == '\x8b':
		return Path(".gzip"), nil
	case hdr[0] == '\x78' && hdr[1] == '\x5E':
		return Path(".Z"), nil
	}
	return nil, nil
}

// Path returns a filetype based strictly on file path.
func Path(path string) *FileType {
	ext := strings.ReplaceAll(filepath.Ext(path), ".", "")
	mime := supportedKind[ext]
	return makeFileType(path, ext, mime)
}
