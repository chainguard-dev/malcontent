// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/rw"
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
	"7z":      "application/x-7z-compressed",
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
	"h":       "text/x-h",
	"hh":      "text/x-h",
	"html":    "",
	"java":    "text/x-java",
	"js":      "application/javascript",
	"ko":      "application/x-object",
	"lnk":     "application/x-ms-shortcut",
	"lua":     "text/x-lua",
	"M":       "text/x-objectivec",
	"m":       "text/x-objectivec",
	"macho":   "application/x-mach-binary",
	"mm":      "text/x-objectivec",
	"md":      "",
	"o":       "application/octet-stream",
	"pe":      "application/vnd.microsoft.portable-executable",
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
	"sh":      "text/x-shellscript",
	"so":      "application/x-sharedlib",
	"ts":      "application/typescript",
	"upx":     "application/x-upx",
	"yaml":    "",
	"yara":    "",
	"yml":     "",
	"zsh":     "application/x-zsh",
}

type FileType struct {
	Ext  string
	MIME string
}

var (
	headerPool     *pool.BufferPool
	initializeOnce sync.Once
	versionRegex   = regexp.MustCompile(`\d+\.\d+\.\d+$`)
	// Magic byte constants for common file signatures.
	elfMagic  = []byte{0x7f, 'E', 'L', 'F'}
	gzipMagic = []byte{0x1f, 0x8b}
	ZMagic    = []byte{0x78, 0x5E}
)

// IsSupportedArchive returns whether a path can be processed by our archive extractor.
// UPX files are an edge case since they may or may not even have an extension that can be referenced.
func IsSupportedArchive(ctx context.Context, path string) bool {
	if _, isValidArchive := ArchiveMap[GetExt(path)]; isValidArchive {
		return true
	}
	if _, ft, err := File(ctx, path); err == nil && ft != nil {
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
	base = versionRegex.ReplaceAllString(base, "")

	ext := filepath.Ext(base)
	if ext == "" {
		return ""
	}

	lastDot := strings.LastIndex(base, ".")
	if lastDot == -1 {
		return ext
	}

	prevDot := strings.LastIndex(base[:lastDot], ".")
	if prevDot != -1 {
		subExt := base[prevDot:]
		if _, ok := ArchiveMap[subExt]; ok {
			return subExt
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
func IsValidUPX(ctx context.Context, header []byte, path string) (bool, error) {
	if !bytes.Contains(header, []byte("UPX!")) {
		return false, nil
	}

	if err := UPXInstalled(); err != nil {
		return false, err
	}

	cmd := exec.CommandContext(ctx, "upx", "-l", "-f", path)
	output, err := cmd.CombinedOutput()

	if err != nil && (bytes.Contains(output, []byte("NotPackedException")) ||
		bytes.Contains(output, []byte("not packed by UPX"))) {
		return false, nil
	}

	return true, nil
}

func makeFileType(path string, ext string, mime string) *FileType {
	ext = strings.TrimPrefix(ext, ".")

	// Archives are supported
	if _, ok := ArchiveMap[GetExt(path)]; ok {
		return &FileType{Ext: ext, MIME: mime}
	}

	// the only JSON files we currently scan are NPM package metadata, which ends in *package.json
	if strings.HasSuffix(path, "package.json") {
		return &FileType{
			Ext:  ext,
			MIME: "application/json",
		}
	}

	if supportedKind[ext] == "" {
		return nil
	}

	// fix mimetype bug that defaults elf binaries to x-sharedlib
	if mime == "application/x-sharedlib" && !strings.Contains(path, ".so") {
		return Path(".elf")
	}

	// fix mimetype bug that detects certain .js files as shellscript
	if mime == "text/x-shellscript" && strings.Contains(path, ".js") {
		return Path(".js")
	}

	if strings.Contains(mime, "application") || strings.Contains(mime, "text/x-") || strings.Contains(mime, "executable") {
		return &FileType{
			Ext:  ext,
			MIME: mime,
		}
	}

	return nil
}

// File returns a file's contents as a byte slice, its file type (extension and MIME type),
// and/or the error encountered when attempting to retrieve either of them.
func File(ctx context.Context, path string) ([]byte, *FileType, error) {
	// Follow symlinks and return cleanly if the target does not exist
	_, err := filepath.EvalSymlinks(path)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}

	st, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat: %w", err)
	}

	if st.IsDir() {
		return nil, nil, nil
	}
	if st.Mode().Type() == fs.ModeIrregular {
		return nil, nil, nil
	}
	if st.Size() == 0 {
		return nil, nil, nil
	}

	initializeHeaderPool()

	buf := headerPool.Get(rw.ReadBuffer) //nolint:nilaway // the buffer pool is created above
	defer headerPool.Put(buf)

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open: %w", err)
	}

	// read the file's contents to determine its type here and to generate reports (if necessary)
	// scanSinglePath originally read the entire file's contents in addition to this function,
	// so it makes sense to read the file's contents once and return them even if we don't end up generating a report (due to filtering, size, etc.)
	// reading the entire file also addresses edge cases where a file's type may not have been identified correctly
	var b bytes.Buffer
	_, err = io.CopyBuffer(&b, io.LimitReader(f, rw.MaxBytes), buf)
	if err != nil {
		return nil, nil, err
	}
	fc := b.Bytes()

	defer func() {
		f.Close()
		b.Reset()
	}()

	// handle any UPX files first which are not supported by mimetype and may be incorrectly identified
	if isUPX, err := IsValidUPX(ctx, fc, path); err == nil && isUPX {
		return fc, Path(".upx"), nil
	}

	// default strategy: mimetype
	mimetype.SetLimit(0)
	mtype := mimetype.Detect(fc)
	if ft := makeFileType(path, mtype.Extension(), mtype.String()); ft != nil {
		return fc, ft, nil
	}

	// fallback strategy: path (extension, mostly)
	if mtype := Path(path); mtype != nil {
		return fc, mtype, nil
	}

	switch {
	case bytes.HasPrefix(fc, elfMagic):
		return fc, Path(".elf"), nil
	case bytes.Contains(fc, []byte("<?php")):
		return fc, Path(".php"), nil
	case bytes.HasPrefix(fc, []byte("import ")):
		return fc, Path(".py"), nil
	case bytes.Contains(fc, []byte(" = require(")):
		return fc, Path(".js"), nil
	case bytes.HasPrefix(fc, []byte("#!/bin/ash")) ||
		bytes.HasPrefix(fc, []byte("#!/bin/bash")) ||
		bytes.HasPrefix(fc, []byte("#!/bin/fish")) ||
		bytes.HasPrefix(fc, []byte("#!/bin/sh")) ||
		bytes.HasPrefix(fc, []byte("#!/bin/zsh")) ||
		bytes.Contains(fc, []byte("if [")) ||
		bytes.Contains(fc, []byte("if !")) ||
		bytes.Contains(fc, []byte("echo ")) ||
		bytes.Contains(fc, []byte("grep ")) ||
		bytes.Contains(fc, []byte("; then")) ||
		bytes.Contains(fc, []byte("export ")) ||
		strings.HasSuffix(path, "profile"):
		return fc, Path(".sh"), nil
	case bytes.HasPrefix(fc, []byte("#!")):
		return fc, Path(".script"), nil
	case bytes.Contains(fc, []byte("#include <")):
		return fc, Path(".c"), nil
	case bytes.Contains(fc, []byte("BEAMAtU8")):
		return fc, Path(".beam"), nil
	case bytes.HasPrefix(fc, gzipMagic):
		return fc, Path(".gzip"), nil
	case bytes.HasPrefix(fc, ZMagic):
		return fc, Path(".Z"), nil
	}

	return nil, nil, nil
}

func initializeHeaderPool() {
	initializeOnce.Do(func() {
		headerPool = pool.NewBufferPool(runtime.GOMAXPROCS(0))
	})
}

// Path returns a filetype based strictly on file path.
func Path(path string) *FileType {
	ext := strings.ReplaceAll(filepath.Ext(path), ".", "")
	mime := supportedKind[ext]
	return makeFileType(path, ext, mime)
}
