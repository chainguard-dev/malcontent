// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package archive extracts archives, compressed files, packages, and OCI
// images into temporary directories for scanning. Extraction writes through an
// os.Root opened on the destination directory, so no archive entry, including
// one that follows a symlink planted by the archive, can read or write outside
// it. Nested archives are extracted recursively; symlinks are never followed.
package archive
