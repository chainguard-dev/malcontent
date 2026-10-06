// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package programkind decides what kind of file a path holds, from its
// extension and content, so malcontent scans programs and scripts and extracts
// archives (including UPX-packed binaries, gzip streams under any name, and
// zlib streams without a recognized extension) while skipping plain data. It
// also locates and validates the UPX binary used to unpack UPX files.
package programkind
