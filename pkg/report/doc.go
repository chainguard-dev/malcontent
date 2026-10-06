// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package report turns YARA-X scan results into malcontent file reports. It
// maps each matching rule to a behavior, scores and levels the risk of each
// behavior and of the file, applies override, ignore, and file-scoping rules,
// renders matched strings, and loads previously written reports.
package report
