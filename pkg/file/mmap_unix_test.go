// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package file

// canMap reports whether loadContents memory-maps large files on this
// platform.
const canMap = true
