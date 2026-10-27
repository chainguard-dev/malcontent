// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// errNotRegular reports an archive path that names something other than a
// regular file, such as a FIFO, whose reads could block forever.
var errNotRegular = errors.New("not a regular file")

// openRegular opens the regular file at path for reading and returns it with
// its FileInfo. The open does not block on a FIFO or a device, and the file is
// examined once open, so that a path replaced after a check still yields only
// a regular file.
func openRegular(path string) (*os.File, fs.FileInfo, error) {
	f, err := file.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("open %q: %w", path, errNotRegular)
	}
	return f, fi, nil
}
