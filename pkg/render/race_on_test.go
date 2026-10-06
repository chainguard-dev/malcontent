// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build race

package render

// raceEnabled reports whether the race detector is on. It drops a share of
// the buffers put in a sync.Pool on purpose.
const raceEnabled = true
