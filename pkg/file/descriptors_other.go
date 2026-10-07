// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package file

// openFileLimit returns how many files the process may have open. Other
// systems set no limit as low as Unix defaults do.
func openFileLimit() int64 { return 1 << 18 }

// growDescriptorTable does nothing: other systems grow their handle tables
// without stalling the process.
func growDescriptorTable(int64) {}
