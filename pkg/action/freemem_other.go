// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !cgo

package action

// releaseFreeMemory does nothing: other C allocators return large freed
// regions to the operating system on their own.
func releaseFreeMemory() {}
