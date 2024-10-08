// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/liamg/magic"
)

var archiveMap = map[string]bool{
	".apk":    true,
	".bz2":    true,
	".bzip2":  true,
	".gem":    true,
	".gz":     true,
	".jar":    true,
	".tar.gz": true,
	".tar.xz": true,
	".tar":    true,
	".tgz":    true,
	".xz":     true,
	".zip":    true,
}

// file extension to mime type
var programFormats = map[string]string{
	"7z":      "",
	"asm":     "",
	"bat":     "application/bat",
	"c":       "C source",
	"cpp":     "C++ source",
	"elf":     "application/x-elf",
	"dll":     "Windows Dynamic Library",
	"cron":    "text/x-crontab",
	"crontab": "text/x-crontab",
	"csh":     "application/x-csh",
	"bin":     "application/octet-stream",
	"expect":  "Expect script",
	"fish":    "Fish script",
	"gem":     "Ruby gem",
	"go":      "Go source",
	"gz":      "Gzip compressed",
	"lua":     "text/x-lua",
	"pl":      "text/x-perl",
	"py":      "text/x-python",
	"h":       "C header",
	"html":    "",
	"js":      "application/javascript",
	"java":    "Java source",
	"js":      "application/javascript",
	"json":    "application/json",
	"md":      "",
	"php":     "text/x-php",
	"macho":   "application/x-mach-binary",
	"pl":      "PERL script",
	"ps1":     "Powershell",
	"py":      "Python script",
	"pyc":     "Python script (compiled)",
	"rb":      "Ruby script",
	"rs":      "Rust source",
	"scpt":    "compiled AppleScript",
	"scptd":   "compiled AppleScript",
	"service": "systemd",
	"so":      "application/x-sharedlib",
	"sh":      "application/x-sh",
	"ts":      "application/typescript",
	"yaml":    "",
	"yara":    "",
	"yml":     "",
	"zsh":     "application/x-sh",
}

// programKind tries to identify if a path is a program.
func programKind(ctx context.Context, path string) string {
	var header [263]byte
	logger := clog.FromContext(ctx).With("path", path)
	f, err := os.Open(path)
	if err != nil {
		logger.Error("os.Open", slog.Any("error", err))
		return ""
	}
	defer f.Close()

	desc := ""
	headerString := ""
	n, err := io.ReadFull(f, header[:])
	if err == nil || errors.Is(err, io.ErrUnexpectedEOF) {
		kind, err := magic.LookupSync(header[:n])
		if err == nil {
			desc = kind.Description
		}
		headerString = string(header[:n])
	}

	// TODO: Is it safe to log unsanitized file stuff?
	logger.Debug("magic", slog.String("desc", desc), slog.String("header", headerString), slog.Any("err", err))

	if found, kind := byExtension(path); found {
		return kind
	}

	d := strings.ToLower(desc)
	switch {
	// By magic
	case strings.Contains(d, "executable") ||
		strings.Contains(d, "mach-o") ||
		strings.Contains(d, "script"):
		return desc
	// By header string
	case strings.Contains(headerString, "import "):
		return "Python script"
	case strings.HasPrefix(headerString, "#!/bin/ash") ||
		strings.HasPrefix(headerString, "#!/bin/bash") ||
		strings.HasPrefix(headerString, "#!/bin/fish") ||
		strings.HasPrefix(headerString, "#!/bin/sh") ||
		strings.HasPrefix(headerString, "#!/bin/zsh") ||
		strings.Contains(headerString, `echo "`) ||
		strings.Contains(headerString, `if [`) ||
		strings.Contains(headerString, `grep `) ||
		strings.Contains(headerString, "if !"):
		return "Shell script"
	case strings.HasPrefix(headerString, "#!"):
		return "script"
	case strings.Contains(headerString, "#include <"):
		return "C Program"
	// By filename or extension
	case strings.Contains(path, "systemd"):
		return "systemd"
	case strings.Contains(path, ".elf"):
		return "Linux ELF binary"
	case strings.Contains(path, ".xcoff"):
		return "XCOFF program"
	case strings.Contains(path, ".dylib"):
		return "macOS dynamic library"
	case strings.HasSuffix(path, "profile"):
		return "Shell script"
	// the magic library gets these wrong
	case strings.HasSuffix(path, ".json"):
		return ""
	}
	return ""
}

// byExtension returns true, and descriptive file type if the extension is
// known, and false otherwise.
func byExtension(path string) (bool, string) {
	ret, ok := extMap[filepath.Ext(path)]
	return ok, ret
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
