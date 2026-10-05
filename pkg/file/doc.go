// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package file holds the buffer sizes malcontent reads and extracts with,
// reads file contents with a strategy chosen by file size (GetContents), and
// accounts for the bytes archive extraction produces so extractors can stop at
// a total-size or expansion-ratio limit (ArchiveCounter).
package file
