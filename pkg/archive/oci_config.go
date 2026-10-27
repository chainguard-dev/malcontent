// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ociConfigScriptName names the file, at the root of each extracted image,
// that holds the image config's Env, Entrypoint, and Cmd as a shell script, so
// that rules for shell scripts see what the container runs. An image file at
// that path wins, and the script takes the first free name of the form
// malcontent-image-config.N.sh instead.
const ociConfigScriptName = "malcontent-image-config.sh"

// ociConfigScriptHeader starts every config script.
const ociConfigScriptHeader = "#!/bin/sh\n" +
	"# Written by malcontent from the image config; not a file in the image.\n" +
	"# Env, then the Entrypoint and Cmd the container runs, one command per line.\n"

// maxOCIConfigBytes bounds the image config read for the script.
const maxOCIConfigBytes = 16 << 20

// ociShells names the programs whose "-c" argument is a shell script.
var ociShells = []string{"ash", "bash", "dash", "ksh", "mksh", "sh", "zsh"}

// writeConfigScript writes the config script for img to root. A config that
// cannot be read is logged and skipped: the filesystem is still scanned.
func writeConfigScript(img v1.Image, root *os.Root, logger *clog.Logger) error {
	m, err := img.Manifest()
	if err != nil {
		return fmt.Errorf("read image manifest: %w", err)
	}
	if m.Config.MediaType != types.DockerConfigJSON && m.Config.MediaType != types.OCIConfigJSON {
		return nil
	}
	if m.Config.Size > maxOCIConfigBytes {
		logger.Warnf("skipping the image config: %d bytes is over the %d byte limit", m.Config.Size, maxOCIConfigBytes)
		return nil
	}
	cf, err := img.ConfigFile()
	if err != nil {
		logger.Warnf("skipping the image config: %v", err)
		return nil
	}
	script := imageConfigScript(cf.Config)
	if script == nil {
		return nil
	}
	for n := 0; ; n++ {
		name := ociConfigScriptName
		if n > 0 {
			name = fmt.Sprintf("malcontent-image-config.%d.sh", n)
		}
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("write image config script: %w", err)
		}
		_, err = f.Write(script)
		return errors.Join(err, f.Close())
	}
}

// imageConfigScript renders cfg as a shell script: one export per Env entry,
// then the Entrypoint and Cmd as one quoted command line. When that command
// runs a shell with -c, the script it passes follows on lines of its own. It
// returns nil when cfg sets none of them.
func imageConfigScript(cfg v1.Config) []byte {
	argv := slices.Concat(cfg.Entrypoint, cfg.Cmd)
	if len(cfg.Env) == 0 && len(argv) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString(ociConfigScriptHeader)
	for _, kv := range cfg.Env {
		b.WriteString("export " + kv + "\n")
	}
	if len(argv) > 0 {
		quoted := make([]string, 0, len(argv))
		for _, a := range argv {
			quoted = append(quoted, shellQuote(a))
		}
		b.WriteString(strings.Join(quoted, " ") + "\n")
		if script, ok := shellScript(argv); ok {
			b.WriteString(script + "\n")
		}
	}
	return []byte(b.String())
}

// shellQuote quotes s as one shell word, leaving words of only safe
// characters bare.
func shellQuote(s string) string {
	const safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@%+=:,./-"
	if s != "" && !strings.ContainsFunc(s, func(r rune) bool { return !strings.ContainsRune(safe, r) }) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellScript returns the argument that follows the first flag holding "c"
// after a shell in argv, such as the script of "/bin/sh -c <script>".
func shellScript(argv []string) (string, bool) {
	shell := false
	for i, a := range argv {
		if !shell {
			shell = slices.Contains(ociShells, path.Base(a))
			continue
		}
		flags, ok := strings.CutPrefix(a, "-")
		if ok && strings.ContainsRune(flags, 'c') && !strings.HasPrefix(flags, "-") && i+1 < len(argv) {
			return argv[i+1], true
		}
	}
	return "", false
}
