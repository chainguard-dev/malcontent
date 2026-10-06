// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package pool provides reusable resources for scanning: BufferPool reuses
// fixed-size byte buffers for copying archive data, and ScannerPool holds a
// bounded set of YARA-X scanners for one compiled rule set.
package pool
