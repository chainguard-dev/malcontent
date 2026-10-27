// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// sidecarName is the file an extraction writes the metadata an archive
// carries outside its entries to: gzip extra and comment fields, zip archive
// and entry comments, tar PAX comment records, and zstd skippable frames. It
// is written beside the extracted content, and only when such metadata is
// present, so that a payload hidden there is scanned rather than deleted with
// the archive. Each record is a label, ": ", the raw bytes, and a newline.
// When an entry of the archive has the same name, the entry keeps it and the
// sidecar takes the first free sibling name: malcontent-metadata_1.bin, then
// malcontent-metadata_2.bin, and so on. The .bin extension makes the scanner
// examine it whatever it holds.
const sidecarName = "malcontent-metadata.bin"

// maxSidecarBytes bounds the metadata one sidecar holds in memory. An archive
// carrying more is reported as holding unaccounted bytes, so that it is
// retained and scanned as it is.
const maxSidecarBytes = 16 << 20

// sidecar collects the metadata of one extraction.
type sidecar struct {
	buf      bytes.Buffer
	overflow bool
}

// add records data under label, unless data is empty.
func (s *sidecar) add(label string, data []byte) {
	if len(data) == 0 {
		return
	}
	if s.buf.Len()+len(label)+len(data)+3 > maxSidecarBytes {
		s.overflow = true
		return
	}
	s.buf.WriteString(label)
	s.buf.WriteString(": ")
	s.buf.Write(data)
	s.buf.WriteByte('\n')
}

// err reports metadata that did not fit.
func (s *sidecar) err() error {
	if s.overflow {
		return fmt.Errorf("%w: metadata exceeds the %d byte sidecar limit", ErrUnaccountedBytes, maxSidecarBytes)
	}
	return nil
}

// writeIn writes the sidecar into dir, a directory as entries name it, after
// every entry has been written, so that an entry of the same name keeps it.
func (s *sidecar) writeIn(p *entryPaths, dir string, b *budget) error {
	if s.buf.Len() == 0 {
		return nil
	}
	if err := chargeSidecar(b, s.buf.Len()); err != nil {
		return err
	}
	out, _, err := p.createFile(filepath.Join(dir, sidecarName))
	if err != nil {
		return fmt.Errorf("failed to create metadata sidecar: %w", err)
	}
	defer out.Close()
	if _, err := out.Write(s.buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write metadata sidecar: %w", err)
	}
	return nil
}

// writeBeside writes the sidecar beside output, the one file a single-stream
// decompressor wrote beneath root.
func (s *sidecar) writeBeside(root *os.Root, output string, b *budget) error {
	if s.buf.Len() == 0 {
		return nil
	}
	if err := chargeSidecar(b, s.buf.Len()); err != nil {
		return err
	}
	out, err := createBeside(root, output)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := out.Write(s.buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write metadata sidecar: %w", err)
	}
	return nil
}

// createBeside creates the sidecar beside output under the first free name.
func createBeside(root *os.Root, output string) (*os.File, error) {
	for name := range collisionNames(filepath.Join(filepath.Dir(output), sidecarName)) {
		if name == output {
			continue
		}
		out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create metadata sidecar: %w", err)
		}
		return out, nil
	}
	return nil, errors.New("failed to create metadata sidecar: no unused name")
}

func chargeSidecar(b *budget, n int) error {
	if err := b.Entry(); err != nil {
		return err
	}
	return b.Add(n)
}
