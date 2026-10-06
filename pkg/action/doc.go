// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package action runs malcontent's scans. Scan matches files, directories,
// archives, and OCI images against compiled YARA-X rules and returns a report
// of each file's behaviors and risk; Diff compares the reports of two scan
// targets. Archives and images are extracted to temporary directories, and
// their entries are reported as "<archive> ∴ <entry path>". The package also
// lists running processes to scan and filters reports by rule category.
package action
