// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gabriel-vasile/mimetype"
)

// file extension to MIME type, if it's a good scanning target.
var supportedKind = map[string]string{
	"7z":      "",
	"asm":     "",
	"bash":    "application/x-bsh",
	"bat":     "application/bat",
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
	"script":  "text/x-generic-script",
	"scpt":    "application/x-applescript",
	"scptd":   "application/x-applescript",
	"service": "text/x-systemd",
	"sh":      "application/x-sh",
	"so":      "application/x-sharedlib",
	"ts":      "application/typescript",
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
func File(path string) (*FileType, error) {
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
	}
	return nil, nil
}

// Path returns a filetype based strictly on file path.
func Path(path string) *FileType {
	ext := strings.ReplaceAll(filepath.Ext(path), ".", "")
	mime := supportedKind[ext]
	return makeFileType(path, ext, mime)
}
