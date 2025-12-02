// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/pool"
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
	if ft, err := File(ctx, path); err == nil && ft != nil {
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
func IsValidUPX(ctx context.Context, fc []byte, path string) (bool, error) {
	if !bytes.Contains(fc, []byte("UPX!")) {
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

	// typically, JSON and YAML files are data files only scanned via --all, but we want to support the NPM ecosystem
	if strings.HasSuffix(path, "package.json") || strings.HasSuffix(path, "package-lock.json") {
		return &FileType{
			Ext:  ext,
			MIME: "application/json",
		}
	}

	if strings.HasSuffix(path, "pnpm-lock.yaml") ||
		strings.HasSuffix(path, "pnpm-workspace.yaml") ||
		strings.HasSuffix(path, "yarn.lock") {
		return &FileType{
			Ext:  ext,
			MIME: "application/x-yaml",
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

// File detects what kind of program this file might be.
func File(ctx context.Context, path string) (*FileType, error) {
	// Follow symlinks and return cleanly if the target does not exist
	_, err := filepath.EvalSymlinks(path)
	if os.IsNotExist(err) {
		return nil, nil
	}

	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	// ignore directories, irregular files, and empty files
	if st.IsDir() || st.Mode().Type() == fs.ModeIrregular || st.Size() == 0 {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	// initialize the header pool after we've successfully opened the file
	initializeHeaderPool()

	// create a buffer sized to the minimum of the file's size or the default ReadBuffer
	buf := headerPool.Get(min(st.Size(), file.ReadBuffer)) //nolint:nilaway // the buffer pool is created above
	defer headerPool.Put(buf)

	fc, err := file.GetContents(f, buf)
	if err != nil {
		return nil, fmt.Errorf("file contents: %w", err)
	}

	// handle UPX files first since mimetype.Detect does not support them
	// and will likely misidentify them
	if isUPX, err := IsValidUPX(ctx, fc, path); err == nil && isUPX {
		return Path(".upx"), nil
	}

	// default strategy: mimetype (no limit for improved magic type detection)
	mimetype.SetLimit(0) // a limit of 0 means the whole input file will be used
	mtype := mimetype.Detect(fc)
	if ft := makeFileType(path, mtype.Extension(), mtype.String()); ft != nil {
		return ft, nil
	}

	// fallback strategy: path (extension, mostly)
	if mtype := Path(path); mtype != nil {
		return mtype, nil
	}

	switch {
	case bytes.HasPrefix(fc, elfMagic):
		return Path(".elf"), nil
	case bytes.Contains(fc, []byte("<?php")):
		return Path(".php"), nil
	case bytes.HasPrefix(fc, []byte("import ")):
		return Path(".py"), nil
	case bytes.Contains(fc, []byte(" = require(")):
		return Path(".js"), nil
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
		return Path(".sh"), nil
	case bytes.HasPrefix(fc, []byte("#!")):
		return Path(".script"), nil
	case bytes.Contains(fc, []byte("#include <")):
		return Path(".c"), nil
	case bytes.Contains(fc, []byte("BEAMAtU8")):
		return Path(".beam"), nil
	case bytes.HasPrefix(fc, gzipMagic):
		return Path(".gzip"), nil
	case bytes.HasPrefix(fc, ZMagic):
		return Path(".Z"), nil
	}

	return nil, nil
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
