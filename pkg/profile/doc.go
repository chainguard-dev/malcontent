// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package profile records CPU, memory, execution-trace, and goroutine
// profiles of a malcontent run into a configurable output directory until
// the profiler is stopped or the process receives SIGINT or SIGTERM.
package profile
