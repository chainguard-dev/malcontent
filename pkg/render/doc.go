// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package render writes malcontent scan and diff reports in the output formats
// the CLI offers. New returns a renderer by name: terminal (the default),
// terminal_brief, markdown, simple, strings, interactive, json, or yaml.
//
// Scan workers call File concurrently. The text renderers render each file
// into a buffer and write it with a single Write, so the output of one file
// never interleaves with another's. The json and yaml renderers write the
// whole report from Full and stream the document rather than building it in
// memory first.
package render
