package action

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/liamg/magic"
	"k8s.io/klog/v2"
)

// programKind tries to identify if a path is a program
func programKind(path string) string {
	var header [263]byte

	f, err := os.Open(path)
	if err != nil {
		log.Printf("os.Open[%s]: %v", path, err)
		return ""
	}
	defer f.Close()

	desc := ""
	if _, err := io.ReadFull(f, header[:]); err == nil {
		kind, err := magic.Lookup(header[:])
		if err == nil {
			desc = kind.Description
		}
	}

	klog.V(1).Infof("desc: %q header: %q err: %v", desc, header[:], err)

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

	switch filepath.Ext(path) {
	case ".scpt", "scptd":
		return "compiled AppleScript"
	case ".sh":
		return "Shell script"
	case ".rb":
		return "Ruby script"
	case ".py":
		return "Python script"
	case ".pl":
		return "PERL script"
	case ".yara":
		return ""
	case ".expect":
		return "Expect script"
	case ".php":
		return "PHP file"
	case ".html":
		return ""
	case ".js":
		return "Javascript"
	case ".ts":
		return "Typescript"
	case ".7z":
		return ""
	case ".json":
		return ""
	case ".yml", ".yaml":
		return ""
	case ".java":
		return "Java source"
	case ".jar":
		return "Java program"
	case ".asm":
		return ""
	case ".c":
		return "C source"
	}

	// By string match
	s := string(header[:])
	switch {
	case strings.Contains(s, "import "):
		return "Python"
	case strings.HasPrefix(s, "#!/bin/sh") || strings.HasPrefix(s, "#!/bin/bash") || strings.Contains(s, `echo "`) || strings.Contains(s, `if [`) || strings.Contains(s, `grep `) || strings.Contains(s, "if !"):
		return "Shell"
	case strings.HasPrefix(s, "#!"):
		return "script"
	case strings.Contains(s, "#include <"):
		return "C Program"
	}

	// fmt.Printf("File %s string: %s", path, s)
	// fmt.Printf("File %s: desc: %s\n", path, desc)
	return ""
}
