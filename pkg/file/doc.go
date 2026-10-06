// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package file holds the buffer sizes malcontent reads and extracts with,
// reads a file's contents once for detection, hashing, and scanning
// (ReadContents memory-maps large files and reads small ones into pooled
// buffers; GetContents returns a plain slice), and accounts for the bytes
// archive extraction produces so extractors can stop at a total-size or
// expansion-ratio limit (ArchiveCounter).
package file
