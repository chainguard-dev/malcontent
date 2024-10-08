// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/gabriel-vasile/mimetype"
)

// file extension to mime type
var knownProgramFormats = map[string]string{
	"7z":      "",
	"asm":     "",
	"bash":    "application/x-bsh",
	"bat":     "application/bat",
	"bin":     "application/octet-stream",
	"c":       "text/x-c",
	"cc":      "text/x-c",
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
	"json":    "application/json",
	"lnk":     "application/x-ms-shortcut",
	"lua":     "text/x-lua",
	"macho":   "application/x-mach-binary",
	"md":      "",
	"o":       "application/octet-stream",
	"php":     "text/x-php",
	"pl":      "text/x-perl",
	"pm":      "text/x-script.perl-module",
	"ps1":     "text/x-powershell",
	"py":      "text/x-script.phyton",
	"pyc":     "application/x-bytecode.python",
	"rb":      "text/x-ruby",
	"rs":      "text/x-rust",
	"scpt":    "application/x-applescript",
	"scptd":   "application/x-applescript",
	"service": "text/x-systemd",
	"sh":      "application/x-sh",
	"so":      "application/x-sharedlib",
	"ts":      "application/typescript",
	"yaml":    "",
	"yara":    "",
	"yml":     "",
	"zsh":     "application/x-zsh",
}

type FileType struct {
	Ext  string
	MIME string
}

func likelyProgram(ext string, mime string) bool {
	if knownProgramFormats[ext] != "" {
		return true
	}
	return strings.Contains(mime, "application") || strings.Contains(mime, "text/x-") || strings.Contains(mime, "text/x-") || strings.Contains(mime, "executable")
}

// ByFile detects what kind of program this file might be
func File(ctx context.Context, path string) (*FileType, error) {
	var header [384]byte
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	_, err = io.ReadFull(f, header[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("read: %w", err)
	}

	// first strategy: detect via MIME magic
	mtype, err := mimetype.DetectFile(path)
	if err == nil {
		clog.Infof("mimetype: %+v", mtype)
		if likelyProgram(mtype.Extension(), mtype.String()) {
			return &FileType{MIME: mtype.String(), Ext: strings.TrimPrefix(mtype.Extension(), ".")}, nil
		}
	}

	// second strategy: detect via path
	return Path(path), nil
}

// ByPath returns a filetype based strictly on file path
func Path(path string) *FileType {
	ext := strings.ReplaceAll(filepath.Ext(path), ".", "")
	mime := knownProgramFormats[ext]
	clog.Infof("by path: %v / %v", ext, mime)
	if mime != "" {
		return &FileType{MIME: mime, Ext: ext}
	}
	return nil
}
