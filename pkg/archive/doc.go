// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package archive extracts archives, compressed files, packages, and OCI
// images into temporary directories for scanning. Extraction writes through an
// os.Root opened on the destination directory, so no archive entry, including
// one that follows a symlink planted by the archive, can read or write outside
// it. Nested archives are extracted recursively; symlinks are never followed.
//
// Extraction never drops content quietly. The format comes from the content,
// whatever a file is named. An entry whose name would leave the destination
// is written beneath it under a cleaned name, and an entry whose path another
// entry took is written under a sibling name, name_1 and so on, rather than
// replacing it. Metadata an archive carries outside its entries, such as gzip
// and zip comments, is written to a sidecar file, malcontent-metadata.bin. An
// archive holding bytes that no entry accounts for is reported with
// ErrUnaccountedBytes, so that it is retained and scanned as it is. Every
// archive in a nested tree charges one byte counter, capped by
// MaxArchiveBytes, and each entry costs a fixed 4 KiB against it besides its
// content.
package archive
