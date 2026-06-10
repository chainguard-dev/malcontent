// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package archive

// CPUQuota is a no-op stub on non-Linux platforms; no cgroup ceiling applies.
func CPUQuota() (int, bool) { return 0, false }
