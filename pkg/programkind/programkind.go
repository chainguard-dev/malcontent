// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"bytes"
	"cmp"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/gabriel-vasile/mimetype"
)

func init() {
	// A limit of 0 lets mimetype examine the whole input, which improves
	// magic type detection. The limit is process-wide, so it is set once.
	mimetype.SetLimit(0)
}

// Supported archive extensions.
var ArchiveMap = map[string]struct{}{
	".apk":     {},
	".bz2":     {},
	".bzip2":   {},
	".deb":     {},
	".ear":     {},
	".gem":     {},
	".gz":      {},
	".gzip":    {},
	".jar":     {},
	".rpm":     {},
	".tar":     {},
	".tar.bz2": {},
	".tar.gz":  {},
	".tar.xz":  {},
	".tbz":     {},
	".tgz":     {},
	".upx":     {},
	".war":     {},
	".whl":     {},
	".xz":      {},
	".zip":     {},
	".zlib":    {},
	".zst":     {},
	".zstd":    {},
}

const (
	mimeGzip        = "application/gzip"
	mimeOctetStream = "application/octet-stream"
	mimeUPX         = "application/x-upx"
	mimeZlib        = "application/zlib"
	mimeShellScript = "text/x-shellscript"
)

// file extension to MIME type, if it's a good scanning target.
var supportedKind = map[string]string{
	"7z":      "application/x-7z-compressed",
	"Z":       mimeZlib,
	"asm":     "",
	"bash":    "application/x-bsh",
	"bat":     "application/bat",
	"beam":    "application/x-erlang-binary",
	"bin":     mimeOctetStream,
	"c":       "text/x-c",
	"cc":      "text/x-c",
	"class":   "application/java-vm",
	"com":     mimeOctetStream,
	"cpp":     "text/x-c",
	"cron":    "text/x-cron",
	"crontab": "text/x-crontab",
	"csh":     "application/x-csh",
	"cxx":     "text/x-c",
	"dic":     "",
	"dll":     mimeOctetStream,
	"dylib":   "application/x-sharedlib",
	"elf":     "application/x-elf",
	"exe":     mimeOctetStream,
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
	"o":       mimeOctetStream,
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
	"sh":      mimeShellScript,
	"so":      "application/x-sharedlib",
	"sqlite":  "",
	"texi":    "",
	"ts":      "application/typescript",
	"txt":     "",
	"upx":     mimeUPX,
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
	// ZMagic is the zlib header written at compression levels 2 through 5.
	// File recognizes any valid zlib header; see isZlibStream.
	ZMagic = []byte{0x78, 0x5E}
	// default, partial MIME types we want to consider as valid by default.
	defaultMIME = []string{
		"application",
		"executable",
		"text/x-",
	}
	elfMagic  = []byte{0x7f, 'E', 'L', 'F'} // ELF magic bytes
	gzipMagic = []byte{0x1f, 0x8b, 0x08}    // gzip magic bytes and the deflate method
	// detectLimit is how many leading bytes of a file Detect examines,
	// matching how much File reads.
	detectLimit = file.MaxBytes
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
)

// IsSupportedArchive returns whether a path can be processed by our archive extractor.
// UPX files are an edge case since they may or may not even have an extension that can be referenced.
func IsSupportedArchive(ctx context.Context, path string) bool {
	if hasArchiveExt(path) {
		return true
	}
	// Content that File recognizes as UPX-packed, gzip, or zlib is extracted
	// whatever the file is named.
	ft, err := File(ctx, path)
	return err == nil && isArchiveKind(ft)
}

// IsSupportedArchiveKind reports whether a file at path whose detected kind is
// ft is handled by the archive extractor. For any regular file File can read,
// IsSupportedArchive(ctx, path) == IsSupportedArchiveKind(path, kind from File).
func IsSupportedArchiveKind(path string, ft *FileType) bool {
	return hasArchiveExt(path) || isArchiveKind(ft)
}

// hasArchiveExt reports whether path's extension names a supported archive.
func hasArchiveExt(path string) bool {
	_, ok := ArchiveMap[GetExt(path)]
	return ok
}

// isArchiveKind reports whether ft is content the archive extractor handles
// whatever the file is named.
func isArchiveKind(ft *FileType) bool {
	return ft != nil && (ft.MIME == mimeUPX || ft.MIME == mimeGzip || ft.MIME == mimeZlib)
}

// GetExt returns the extension of a file path
// and attempts to avoid including fragments of filenames with other dots before the extension.
func GetExt(path string) string {
	// Handle files with version numbers in the name,
	// e.g. composer-2.7.7 has no extension rather than .7
	base := stripVersionSuffix(filepath.Base(path))

	// ext begins at the last dot in base. When base has no dot, ext is empty
	// and the search below finds none, so the result is empty too.
	ext := filepath.Ext(base)
	lastDot := len(base) - len(ext)
	if prevDot := strings.LastIndexByte(base[:lastDot], '.'); prevDot != -1 {
		subExt := base[prevDot:]
		if _, ok := ArchiveMap[subExt]; ok {
			return subExt
		}
	}

	return ext
}

// stripVersionSuffix removes a trailing version number of the form N.N.N,
// where each N is one or more ASCII digits, from s: 1.2.3.4.5 becomes 1.2.,
// and the whole leading digit run goes, so a12.34.56 becomes a.
func stripVersionSuffix(s string) string {
	end := len(s)
	// The last two digit runs must each be preceded by a dot.
	for range 2 {
		start := digitRunStart(s, end)
		if start == end || start == 0 || s[start-1] != '.' {
			return s
		}
		end = start - 1
	}
	start := digitRunStart(s, end)
	if start == end {
		return s
	}
	return s[:start]
}

// digitRunStart returns the index where the run of ASCII digits ending at
// s[end-1] begins, or end when s[end-1] is not a digit.
func digitRunStart(s string, end int) int {
	for end > 0 && s[end-1] >= '0' && s[end-1] <= '9' {
		end--
	}
	return end
}

var (
	// ErrUPXNotFound reports that no usable UPX binary was discovered on the
	// automatic discovery path (MALCONTENT_UPX_PATH unset).
	ErrUPXNotFound = errors.New("UPX executable not found")
	// ErrUPXPathInvalid reports that an operator-supplied MALCONTENT_UPX_PATH
	// failed validation. The wrapped error names the specific reason.
	ErrUPXPathInvalid = errors.New("MALCONTENT_UPX_PATH is invalid")
)

const defaultUPXPath = "/usr/bin/upx"

// upxAllowedPrefixes lists directories from which a UPX binary may be loaded
// during automatic discovery (MALCONTENT_UPX_PATH unset). An operator who sets
// MALCONTENT_UPX_PATH explicitly bypasses this allowlist; their path is trusted
// after the per-path safety checks in validateUPXPath.
var upxAllowedPrefixes = []string{
	"/usr/bin/",
	"/usr/local/bin/",
	"/opt/homebrew/bin/",
}

// Homebrew Cellar paths are versioned (e.g. /opt/homebrew/Cellar/upx/5.1.1/bin/upx),
// so the resolved path is matched by prefix rather than exact parent directory.
var upxAllowedResolvedPrefixes = []string{
	"/opt/homebrew/Cellar/upx/",
}

// validateUPXPath resolves and vets a candidate UPX binary path.
//
// Every candidate must be an absolute path that resolves cleanly through
// EvalSymlinks to a regular, executable file that is not group- or
// world-writable.
//
// When operatorSupplied is true (MALCONTENT_UPX_PATH was set), the resolved
// path is trusted regardless of its directory: the operator has made an
// explicit trust assertion. When operatorSupplied is false (automatic
// discovery via the default path), the resolved path must additionally live
// directly under one of the well-known UPX install prefixes.
func validateUPXPath(p string, operatorSupplied bool) (string, error) {
	if p == "" {
		return "", errors.New("empty upx path")
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("upx path must be absolute: %q", p)
	}
	cleaned := filepath.Clean(p)
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("upx path resolve failed: %w", err)
	}

	fi, err := file.LstatIn(filepath.Dir(resolved), filepath.Base(resolved))
	if err != nil {
		return "", fmt.Errorf("upx path stat failed: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("upx path is not a regular file: %q", resolved)
	}
	if fi.Mode()&0o111 == 0 {
		return "", fmt.Errorf("upx path is not executable: %q", resolved)
	}
	if fi.Mode()&0o022 != 0 {
		return "", fmt.Errorf("upx path is group- or world-writable: %q", resolved)
	}

	if operatorSupplied {
		return resolved, nil
	}

	parent := filepath.Dir(resolved) + "/"
	if slices.Contains(upxAllowedPrefixes, parent) {
		return resolved, nil
	}
	for _, prefix := range upxAllowedResolvedPrefixes {
		if strings.HasPrefix(resolved, prefix) && strings.HasSuffix(parent, "/bin/") {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("upx path %q not in allowlist [%s, %s]", resolved, strings.Join(upxAllowedPrefixes, ", "), strings.Join(upxAllowedResolvedPrefixes, ", "))
}

// upxLookup is the outcome of locating the UPX binary for one value of
// MALCONTENT_UPX_PATH.
type upxLookup struct {
	env  string
	path string
	err  error
}

// upxCache holds the most recent lookup, so the binary is resolved and vetted
// once per MALCONTENT_UPX_PATH value rather than for every suspected UPX
// file. Keying on the value lets a changed setting take effect.
var upxCache atomic.Pointer[upxLookup]

// UPXInstalled returns the resolved path to the UPX binary, or an error if not found.
//
// When MALCONTENT_UPX_PATH is set, it is treated as an explicit operator trust
// assertion: the path bypasses the directory allowlist but must still pass the
// per-path safety checks, and any failure is surfaced as a specific
// ErrUPXPathInvalid reason rather than a generic "not found".
//
// The result is cached until MALCONTENT_UPX_PATH changes.
func UPXInstalled() (string, error) {
	env := os.Getenv("MALCONTENT_UPX_PATH")
	if c := upxCache.Load(); c != nil && c.env == env {
		return c.path, c.err
	}
	path, err := findUPX(env)
	upxCache.Store(&upxLookup{env: env, path: path, err: err})
	return path, err
}

// findUPX resolves and vets the UPX binary named by operatorPath, the value of
// MALCONTENT_UPX_PATH, or the default path when it is empty.
func findUPX(operatorPath string) (string, error) {
	operatorSupplied := operatorPath != ""
	candidate := cmp.Or(operatorPath, defaultUPXPath)

	upxPath, err := validateUPXPath(candidate, operatorSupplied)
	if err != nil {
		if operatorSupplied {
			// The operator asked for a specific binary; tell them why it was
			// rejected instead of hiding the reason behind "not found".
			return "", fmt.Errorf("%w: %w", ErrUPXPathInvalid, err)
		}
		// Automatic discovery failed; extractors skip the UPX path. Do not
		// surface attacker-controlled details further.
		return "", ErrUPXNotFound
	}

	return upxPath, nil
}

// IsValidUPX checks whether a suspected UPX-compressed file can be decompressed with UPX.
func IsValidUPX(ctx context.Context, fc []byte, path string) (bool, error) {
	if !bytes.Contains(fc, []byte("UPX!")) {
		return false, nil
	}

	upxPath, err := UPXInstalled()
	if err != nil {
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

	cmd := exec.CommandContext(ctx, upxPath, "-l", "-f", "--", absPath) // #nosec G204 -- invokes pinned upx binary with validated absolute path arg
	output, err := cmd.CombinedOutput()

	if err != nil && (bytes.Contains(output, []byte("NotPackedException")) ||
		bytes.Contains(output, []byte("not packed by UPX"))) {
		return false, nil
	}

	return true, nil
}

func makeFileType(path string, ext string, mime string) *FileType {
	ext = strings.TrimPrefix(ext, ".")

	// Archives are supported. ArchiveMap keys keep their leading dot, so only
	// the path's extension, never the trimmed ext, can match one.
	if _, ok := ArchiveMap[GetExt(path)]; ok {
		return &FileType{Ext: ext, MIME: mime}
	}

	// by default, JSON files will not have a defined MIME type,
	// but we want to specifically target the NPM ecosystem
	// using --all or --include-data-files will override these distinctions
	if containsSuffix(path, npmJSON) {
		return &FileType{Ext: ext, MIME: "application/json"}
	}
	// by default, YAML files will also not have a defined MIME type,
	// but we want to specifically target the NPM ecosystem
	// using --all or --include-data-files will override these distinctions
	if containsSuffix(path, npmYAML) {
		return &FileType{Ext: ext, MIME: "application/x-yaml"}
	}
	// the ordering of this statement is important
	// placing it first would prevent the preceding JSON/YAML statements from taking effect
	if supportedKind[ext] == "" {
		return nil
	}
	// the following statements are not at risk of being preempted by the preceding statement
	// fix mimetype bug that defaults elf binaries to x-sharedlib
	if mime == "application/x-sharedlib" && !strings.Contains(path, ".so") {
		return Path(".elf")
	}
	// fix mimetype bug that detects certain .js files as shellscript
	if mime == mimeShellScript && strings.Contains(path, ".js") {
		return Path(".js")
	}
	// treat all other MIME types as valid
	if containsValue(mime, defaultMIME) {
		return &FileType{Ext: ext, MIME: mime}
	}
	return nil
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

	// The "profile" suffix also covers .bash_profile and .zsh_profile.
	if strings.HasSuffix(path, "profile") ||
		strings.HasSuffix(path, ".bashrc") ||
		strings.HasSuffix(path, ".zshrc") {
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

// Bounds on the work spent confirming a zlib header: at most zlibProbeInput
// bytes (64 KiB) of the stream are inflated, stopping after zlibProbeOutput
// bytes.
const (
	zlibProbeInput  = 64 << 10
	zlibProbeOutput = 512
)

// isZlibStream reports whether fc begins with a zlib stream (RFC 1950) at any
// compression level. A valid two-byte header can occur by chance in other
// data, so a candidate is confirmed by inflating a bounded prefix. Running out
// of input after some data inflated is accepted because the prefix may cut the
// stream short; header, checksum, and deflate data errors are not.
func isZlibStream(fc []byte) bool {
	if len(fc) < 2 {
		return false
	}
	// Only deflate (method 8) with a window of at most 32 KiB, header check
	// bits that divide by 31, and no preset dictionary can begin a zlib stream
	// here. Checking these first keeps most files from allocating a
	// decompressor; the dictionary flag must be checked regardless, because
	// zlib.NewReader accepts a dictionary ID that matches an empty dictionary.
	cmf, flg := fc[0], fc[1]
	if cmf&0x0f != 8 || cmf>>4 > 7 || (uint16(cmf)<<8|uint16(flg))%31 != 0 || flg&0x20 != 0 {
		return false
	}

	// Closing a zlib reader only records that it is closed; there is nothing
	// to release, so zr is not closed.
	zr, err := zlib.NewReader(bytes.NewReader(fc[:min(len(fc), zlibProbeInput)]))
	if err != nil {
		return false
	}

	n, err := io.CopyN(io.Discard, zr, zlibProbeOutput)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// A cut-short stream counts only once it has inflated some data; a
		// bare header is no evidence of zlib.
		return n > 0
	}
	return err == nil || errors.Is(err, io.EOF)
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
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	// A resolved path ending in one of these names is a directory, which is
	// ignored.
	name := filepath.Base(resolved)
	switch name {
	case ".", "..", string(filepath.Separator):
		return nil, nil
	}

	// Only a regular, non-empty file is opened; anything else yields no file
	// and the error, if examining it failed.
	f, size, err := openContent(filepath.Dir(resolved), name)
	if f == nil {
		return nil, err
	}
	fc, err := file.ReadContents(f, size)
	// The contents stay valid after the file is closed.
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("file contents: %w", err)
	}
	defer func() { _ = fc.Close() }()

	return Detect(ctx, path, fc.Bytes()), nil
}

// openContent opens name beneath dir, through a root on dir, when it is a
// regular, non-empty file and returns it with its size. Anything else yields
// no file and no error.
func openContent(dir, name string) (*os.File, int64, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("stat: %w", err)
	}
	defer func() { _ = root.Close() }()

	st, err := root.Stat(name)
	if err != nil {
		return nil, 0, fmt.Errorf("stat: %w", err)
	}

	// ignore directories, irregular files, and empty files
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return nil, 0, nil
	}

	f, err := root.Open(name)
	if err != nil {
		return nil, 0, fmt.Errorf("open: %w", err)
	}
	return f, st.Size(), nil
}

// Detect returns the kind of the file at path whose contents are fc: exactly
// what File returns for a regular, non-empty file with those contents. Like
// File, it examines at most the first file.MaxBytes of fc, and it may run the
// UPX binary against path when fc holds the UPX marker.
func Detect(ctx context.Context, path string, fc []byte) *FileType {
	fc = fc[:min(int64(len(fc)), detectLimit)]

	// handle UPX files first since mimetype.Detect does not support them
	// and will likely misidentify them
	if isUPX, err := IsValidUPX(ctx, fc, path); err == nil && isUPX {
		return Path(".upx")
	}

	// gzip content is an archive whatever the file is named; this is the
	// same type a .gz name yields
	if bytes.HasPrefix(fc, gzipMagic) {
		return &FileType{Ext: "gz", MIME: mimeGzip}
	}

	// default strategy: mimetype, examining the whole input (see init)
	mtype := mimetype.Detect(fc)
	ext, mime := mtype.Extension(), mtype.String()
	if ft := makeFileType(path, ext, mime); ft != nil {
		return ft
	}

	// fallback strategy: path (extension, mostly)
	if ft := Path(path); ft != nil {
		return ft
	}

	pathExt := strings.TrimPrefix(GetExt(path), ".")

	// Content-based detection for files with no recognized extension or mimetype.
	// If we track an extension in our supportedKind map and the file's type is still nil,
	// return nil (e.g., valid JSON or YAML files that we want to treat as data files by default)
	if _, known := supportedKind[pathExt]; known {
		return nil
	}
	if mime == mimeOctetStream && len(pathExt) >= 2 {
		return nil
	}
	if strings.Contains(mime, "text/plain") && isLikelyManPage(path) {
		return nil
	}
	if bytes.HasPrefix(fc, elfMagic) {
		return Path(".elf")
	}
	if bytes.Contains(fc, []byte("<?php")) {
		return Path(".php")
	}
	if bytes.HasPrefix(fc, []byte("import ")) {
		return Path(".py")
	}
	if bytes.Contains(fc, []byte(" = require(")) {
		return Path(".js")
	}
	if isLikelyShellScript(fc, path) {
		return Path(".sh")
	}
	if bytes.HasPrefix(fc, []byte("#!")) {
		return Path(".script")
	}
	if bytes.Contains(fc, []byte("#include <")) {
		return Path(".c")
	}
	if bytes.Contains(fc, []byte("BEAMAtU8")) {
		return Path(".beam")
	}
	if isZlibStream(fc) {
		return Path(".Z")
	}
	return nil
}

// Path returns a filetype based strictly on file path.
func Path(path string) *FileType {
	ext := strings.TrimPrefix(GetExt(path), ".")
	mime := supportedKind[ext]
	return makeFileType(path, ext, mime)
}
