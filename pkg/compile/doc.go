// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package compile builds the YARA-X rule set malcontent scans with. Recursive
// compiles every .yara and .yar file in the given filesystems, dropping noisy
// third-party rules first; RecursiveCached does the same but reuses a compiled
// rule set saved in the user cache directory, guarded by a SHA-256 integrity
// sidecar and keyed by the rule sources and the yara-x version.
package compile
