// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/liamg/magic"
	"k8s.io/klog/v2"
)

// map from extensions to program kinds.
var extMap = map[string]string{
	".scpt":    "compiled AppleScript",
	".scptd":   "compiled AppleScript",
	".sh":      "Shell script",
	".rb":      "Ruby script",
	".py":      "Python script",
	".pl":      "PERL script",
	".yara":    "",
	".expect":  "Expect script",
	".php":     "PHP file",
	".html":    "",
	".js":      "Javascript",
	".ts":      "Typescript",
	".7z":      "",
	".json":    "",
	".yml":     "",
	".yaml":    "",
	".java":    "Java source",
	".jar":     "Java program",
	".asm":     "",
	".service": "systemd",
	".cron":    "crontab",
	".crontab": "crontab",
	".c":       "C source",
}

// programKind tries to identify if a path is a program.
func programKind(path string) string {
	var header [263]byte
	f, err := os.Open(path)
	if err != nil {
		log.Printf("os.Open[%s]: %v", path, err)
		return ""
	}
	defer f.Close()

	desc := ""
	var headerString string
	n, err := io.ReadFull(f, header[:])
	switch {
	case err == nil || errors.Is(err, io.ErrUnexpectedEOF):
		// Read the full buffer, or some bytes, all good
		kind, err := magic.Lookup(header[:n])
		if err == nil {
			desc = kind.Description
		} else {
			desc = ""
		}
		headerString = string(header[:n])
	case errors.Is(err, io.EOF):
		// Nothing was read, so set the buffer so.
		desc = ""
		headerString = ""
	}

	// TODO: Is it safe to log unsanitized file stuff?
	klog.V(1).Infof("desc: %q header: %q err: %v", desc, headerString, err)

	// the magic library gets these wrong
	if strings.HasSuffix(path, ".json") {
		return ""
	}

	// By Magic
	d := strings.ToLower(desc)
	if strings.Contains(d, "executable") || strings.Contains(d, "mach-o") || strings.Contains(d, "script") {
		return desc
	}

	// By Filename
	switch {
	case strings.Contains(path, "systemd"):
		return "systemd"
	case strings.Contains(path, ".elf"):
		return "Linux ELF binary"
	case strings.Contains(path, ".xcoff"):
		return "XCOFF progam"
	case strings.Contains(path, ".dylib"):
		return "macOS dynamic library"
	case strings.HasSuffix(path, "profile"):
		return "Shell script"
	}

	if found, kind := byExtension(path); found {
		return kind
	}

	// By string match
	switch {
	case strings.Contains(headerString, "import "):
		return "Python script"
	case strings.HasPrefix(headerString, "#!/bin/sh") || strings.HasPrefix(headerString, "#!/bin/bash") || strings.Contains(headerString, `echo "`) || strings.Contains(headerString, `if [`) || strings.Contains(headerString, `grep `) || strings.Contains(headerString, "if !"):
		return "Shell script"
	case strings.HasPrefix(headerString, "#!"):
		return "script"
	case strings.Contains(headerString, "#include <"):
		return "C Program"
	}
	return ""
}

// byExtension returns true, and descriptive file type if the extension is
// known, and false otherwise.
func byExtension(path string) (bool, string) {
	ret, ok := extMap[filepath.Ext(path)]
	return ok, ret
}
