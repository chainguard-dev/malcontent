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

// file extension to MIME type, if it's a good scanning target
var supportedKind = map[string]string{
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

func makeFileType(path string, ext string, mime string) *FileType {
	clog.Infof("makeFileType: path=%s ext=%s mime=%s", path, ext, mime)
	ext = strings.TrimPrefix(ext, ".")
	if supportedKind[ext] == "" {
		return nil
	}

	// fix mimetype bug that defaults elf binaries to x-sharedlib
	if mime == "application/x-sharedlib" && !strings.Contains(path, ".so") {
		return Path(".elf")
	}

	if strings.Contains(mime, "application") || strings.Contains(mime, "text/x-") || strings.Contains(mime, "text/x-") || strings.Contains(mime, "executable") {
		clog.Infof("supported: %s / %s", mime, ext)
		return &FileType{MIME: mime, Ext: ext}
	}

	return nil
}

// File detects what kind of program this file might be
func File(ctx context.Context, path string) (*FileType, error) {
	clog.Infof("path: %s", path)

	// first strategy: mimetype
	mtype, err := mimetype.DetectFile(path)
	if err == nil {
		clog.Infof("mimetype: %+v", mtype)
		if ft := makeFileType(path, mtype.Extension(), mtype.String()); ft != nil {
			return ft, nil
		}
	}

	// second strategy: path (extension, mostly)
	if mtype := Path(path); mtype != nil {
		return mtype, nil
	}

	// read header content for future strategies
	var header [263]byte
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	_, err = io.ReadFull(f, header[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, nil
	}

	// final strategy: DIY
	content := string(header[:])
	fmt.Printf("content for %s - %s", path, content)
	switch {
	case strings.HasPrefix(content, "#!/bin/sh"):
		return Path(".sh"), nil
	case strings.HasPrefix(content, "#!/bin/bash"):
		return Path(".bash"), nil
	}

	return nil, nil
}

// Path returns a filetype based strictly on file path
func Path(path string) *FileType {
	ext := strings.ReplaceAll(filepath.Ext(path), ".", "")
	mime := supportedKind[ext]
	clog.Infof("by path: %v / %v", ext, mime)
	if mime != "" {
		return &FileType{MIME: mime, Ext: ext}
	}
	return nil
}
