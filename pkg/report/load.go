// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// tempDirPattern matches the temporary directory root at the start of a path
// extracted under macOS or /tmp.
var tempDirPattern = regexp.MustCompile(`^/(?:var/folders|tmp|private/var/folders|private/tmp)/[^/]+/[^/]+/T/[^/]+`)

func Load(data []byte) (malcontent.ScanResult, error) {
	var report malcontent.ScanResult
	if err := json.Unmarshal(data, &report); err != nil {
		return report, err
	}
	return report, nil
}

// ExtractImageURI extracts the image URI from paths in a report.
func ExtractImageURI(files map[string]*malcontent.FileReport) string {
	for _, fr := range files {
		if fr == nil || strings.HasPrefix(fr.Path, "/") {
			continue
		}

		// Only the " ∴ " separator malcontent writes marks an image URI. A
		// file name that merely contains "∴" is not one.
		if uri, _, ok := strings.Cut(fr.Path, " ∴ "); ok {
			return strings.TrimSpace(uri)
		}
	}
	return ""
}

// ExtractTmpRoot extracts the temporary directory root from paths in a report.
func ExtractTmpRoot(files map[string]*malcontent.FileReport) string {
	for _, fr := range files {
		if fr == nil {
			continue
		}

		// An empty path has no root.
		if root := tempDirPattern.FindString(fr.Path); root != "" {
			return root
		}
	}

	return ""
}

// CleanReportPath preserves existing image URIs in a path
// or removes the temporary directory root from a path.
func CleanReportPath(path, tmpRoot, imageURI string) string {
	if path == "" {
		return path
	}

	// If path already has the image URI, it's already clean
	if imageURI != "" && strings.HasPrefix(path, imageURI) {
		return path
	}

	// Remove the temp directory prefix if present, then any remaining temp
	// dir root
	path = strings.TrimPrefix(path, tmpRoot)
	path = strings.TrimPrefix(path, tempDirPattern.FindString(path))

	// Ensure path starts with / (unless it has an imageURI prefix)
	if !strings.HasPrefix(path, "/") && (imageURI == "" || !strings.HasPrefix(path, imageURI)) {
		path = "/" + path
	}

	return path
}

// FormatReportKey creates an appropriate key for a file from a loaded report.
func FormatReportKey(path, tmpRoot, imageURI string) string {
	if path == "" {
		return path
	}

	if imageURI != "" && strings.HasPrefix(path, imageURI) {
		return path
	}

	clean := strings.TrimPrefix(path, tmpRoot)
	clean = strings.TrimPrefix(clean, tempDirPattern.FindString(clean))

	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}

	if imageURI != "" {
		return imageURI + " ∴ " + clean
	}

	return clean
}
