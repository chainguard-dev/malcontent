// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
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
	".zip":    true,
	".zlib":   true,
	".zst":    true,
	".zstd":   true,
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
	"dic":     "",
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
	"json":    "",
	"ko":      "application/x-object",
	"lnk":     "application/x-ms-shortcut",
	"lua":     "text/x-lua",
	"M":       "text/x-objectivec",
	"m":       "text/x-objectivec",
	"macho":   "application/x-mach-binary",
	"mm":      "text/x-objectivec",
	"md":      "",
	"o":       "application/octet-stream",
	"pdf":     "",
	"pe":      "application/vnd.microsoft.portable-executable",
	"php":     "text/x-php",
	"pl":      "text/x-perl",
	"pm":      "text/x-script.perl-module",
	"ps1":     "text/x-powershell",
	"py":      "text/x-python",
	"pyc":     "application/x-python-code",
	"rb":      "text/x-ruby",
	"rs":      "text/x-rust",
	"rst":     "",
	"scpt":    "application/x-applescript",
	"scptd":   "application/x-applescript",
	"script":  "text/x-generic-script",
	"service": "text/x-systemd",
	"sh":      "text/x-shellscript",
	"so":      "application/x-sharedlib",
	"sqlite":  "",
	"texi":    "",
	"ts":      "application/typescript",
	"txt":     "",
	"upx":     "application/x-upx",
	"vbs":     "text/x-vbscript",
	"vim":     "text/x-vim",
	"xml":     "",
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
	ZMagic = []byte{0x78, 0x5E} // Z magic bytes
	// default, partial MIME types we want to consider as valid by default.
	defaultMIME = []string{
		"application",
		"executable",
		"text/x-",
	}
	elfMagic       = []byte{0x7f, 'E', 'L', 'F'} // ELF magic bytes
	gzipMagic      = []byte{0x1f, 0x8b}          // gZip magic bytes
	headerPool     *pool.BufferPool
	initializeOnce sync.Once
	// supported NPM JSON extensions or file names we want to avoid classifying as data files.
	npmJSON = []string{
		".js.map",
		"package-lock.json",
		"package.json",
	}
	// supported NPM YAML file names we want to avoid classsifying as data files.
	npmYAML = []string{
		"pnpm-lock.yaml",
		"pnpm-workspace.yaml",
		"yarn.lock",
	}
	shellPatterns = [][]byte{
		[]byte("; then\n"),
		[]byte("; do\n"),
		[]byte("esac"),
		[]byte("fi\n"),
		[]byte("done\n"),
		[]byte("$(("),
		[]byte("$("),
		[]byte("${"),
		[]byte("<<EOF"),
		[]byte("<<-EOF"),
		[]byte("<<'EOF'"),
		[]byte("|| exit"),
		[]byte("&& exit"),
		[]byte("set -e"),
		[]byte("set -x"),
		[]byte("set -u"),
		[]byte("set -o "),
		[]byte("export PATH"),
	}
	shellShebangs = [][]byte{
		[]byte("#!/bin/ash"),
		[]byte("#!/bin/bash"),
		[]byte("#!/bin/dash"),
		[]byte("#!/bin/fish"),
		[]byte("#!/bin/ksh"),
		[]byte("#!/bin/sh"),
		[]byte("#!/bin/zsh"),
		[]byte("#!/usr/bin/env bash"),
		[]byte("#!/usr/bin/env sh"),
		[]byte("#!/usr/bin/env zsh"),
	}
	versionRegex = regexp.MustCompile(`\d+\.\d+\.\d+$`)
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

var ErrUPXNotFound = errors.New("UPX executable not found")

const defaultUPXPath = "/usr/bin/upx"

func UPXInstalled() error {
	upxPath := cmp.Or(os.Getenv("MALCONTENT_UPX_PATH"), defaultUPXPath)

	fi, err := os.Stat(upxPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrUPXNotFound
		}
		return fmt.Errorf("failed to check for UPX executable: %w", err)
	}
	if fi.Mode()&0o111 != 0o111 {
		return fmt.Errorf("provided UPX binary is not executable")
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

	base := filepath.Base(path)
	if strings.HasPrefix(path, "-") || strings.HasPrefix(base, "-") {
		return false, fmt.Errorf("path and/or file begins with '-': %q", path)
	}
	if len(base) > 255 {
		return false, fmt.Errorf("file name exceeds 255 characters")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	cmd := exec.CommandContext(ctx, "upx", "-l", "-f", "--", absPath)
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
	if _, ok := ArchiveMap[ext]; ok {
		return &FileType{Ext: ext, MIME: mime}
	}
	if _, ok := ArchiveMap[GetExt(path)]; ok {
		return &FileType{Ext: ext, MIME: mime}
	}

	switch {
	// by default, JSON files will not have a defined MIME type,
	// but we want to specifically target the NPM ecosystem
	// using --all or --include-data-files will override these distinctions
	case containsSuffix(path, npmJSON):
		return &FileType{Ext: ext, MIME: "application/json"}
	// by default, YAML files will also not have a defined MIME type,
	// but we want to specifically target the NPM ecosystem
	// using --all or --include-data-files will override these distinctions
	case containsSuffix(path, npmYAML):
		return &FileType{Ext: ext, MIME: "application/x-yaml"}
	// the ordering of this statement is important
	// placing it first would prevent the preceding JSON/YAML statemments from taking effect
	case supportedKind[ext] == "":
		return nil
	// the follwing statements are not at risk of being preempted by the preceding statement
	// fix mimetype bug that defaults elf binaries to x-sharedlib
	case mime == "application/x-sharedlib" && !strings.Contains(path, ".so"):
		return Path(".elf")
	// fix mimetype bug that detects certain .js files as shellscript
	case mime == "text/x-shellscript" && strings.Contains(path, ".js"):
		return Path(".js")
	// treat all other MIME types as valid
	case containsValue(mime, defaultMIME):
		return &FileType{Ext: ext, MIME: mime}
	default:
		return nil
	}
}

// isLikelyShellScript determines if a file's content resembles a shell script
// and focuses on multiple criteria to reduce false-positives.
func isLikelyShellScript(fc []byte, path string) bool {
	if isLikelyManPage(path) {
		return false
	}

	if slices.ContainsFunc(shellShebangs, func(shebang []byte) bool {
		return bytes.HasPrefix(fc, shebang)
	}) {
		return true
	}

	if strings.HasSuffix(path, "profile") ||
		strings.HasSuffix(path, ".bashrc") ||
		strings.HasSuffix(path, ".bash_profile") ||
		strings.HasSuffix(path, ".zshrc") ||
		strings.HasSuffix(path, ".zsh_profile") {
		return true
	}

	matches := 0
	for _, pattern := range shellPatterns {
		if bytes.Contains(fc, pattern) {
			matches++
			if matches >= 2 {
				return true
			}
		}
	}

	return false
}

// isLikelyManPage checks a file's path and its extension to determine
// if it is a man page (e.g., usr/share/man/man7/parallel_examples.7).
func isLikelyManPage(path string) bool {
	if strings.Contains(path, "usr/share/man/") {
		if _, err := strconv.Atoi(strings.TrimPrefix(GetExt(path), ".")); err == nil {
			return true
		}
	}
	return false
}

// containsSuffix determines whether a value contains any of the specified strings as a suffix.
func containsSuffix(value string, slice []string) bool {
	return slices.ContainsFunc(slice, func(s string) bool {
		return strings.HasSuffix(value, s)
	})
}

// containsValue determines whether a value contains any of the specified substrings.
func containsValue(value string, slice []string) bool {
	return slices.ContainsFunc(slice, func(s string) bool {
		return strings.Contains(value, s)
	})
}

// File detects what kind of program this file might be.
func File(ctx context.Context, path string) (*FileType, error) {
	// Follow symlinks and return cleanly if the target does not exist
	_, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
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
	ext, mime := mtype.Extension(), mtype.String()
	if ft := makeFileType(path, ext, mime); ft != nil {
		return ft, nil
	}

	// fallback strategy: path (extension, mostly)
	if mtype := Path(path); mtype != nil {
		return mtype, nil
	}

	pathExt := strings.TrimPrefix(GetExt(path), ".")

	_, pathExtKnown := supportedKind[pathExt]

	// Content-based detection for files with no recognized extension or mimetype
	switch {
	// if we track an extension in our supportedKind map and the files's type is still nil,
	// return nil (e.g., valid JSON or YAML files that we want to treat as data files by default)
	case pathExtKnown:
		return nil, nil
	case mime == "application/octet-stream" && len(pathExt) >= 2:
		return nil, nil
	case strings.Contains(mime, "text/plain") && isLikelyManPage(path):
		return nil, nil
	case bytes.HasPrefix(fc, elfMagic):
		return Path(".elf"), nil
	case bytes.Contains(fc, []byte("<?php")):
		return Path(".php"), nil
	case bytes.HasPrefix(fc, []byte("import ")):
		return Path(".py"), nil
	case bytes.Contains(fc, []byte(" = require(")):
		return Path(".js"), nil
	case isLikelyShellScript(fc, path):
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
	default:
		return nil, nil
	}
}

func initializeHeaderPool() {
	initializeOnce.Do(func() {
		headerPool = pool.NewBufferPool(runtime.GOMAXPROCS(0))
	})
}

// Path returns a filetype based strictly on file path.
func Path(path string) *FileType {
	ext := strings.TrimPrefix(GetExt(path), ".")
	mime := supportedKind[ext]
	return makeFileType(path, ext, mime)
}
