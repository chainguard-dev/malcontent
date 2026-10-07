// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package action

// memoryLimit reports no known limit, so large scans are not budgeted.
func memoryLimit() int64 { return 0 }
