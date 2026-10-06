// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"

	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

// detectFileType returns a function that detects the type of the file at path
// when called, reporting nil when detection fails. Detection reads the whole
// file, so extractors call the function only when the type decides how they
// read it.
func detectFileType(ctx context.Context, path string) func() *programkind.FileType {
	return func() *programkind.FileType {
		ft, err := programkind.File(ctx, path)
		if err != nil {
			return nil
		}
		return ft
	}
}
