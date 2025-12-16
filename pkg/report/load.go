package report

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

var tempDirPattern = regexp.MustCompile(`^(/(?:var/folders|tmp|private/var/folders|private/tmp)/[^/]+/[^/]+/T/[^/]+)`)

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
		if fr == nil || fr.Path == "" {
			continue
		}

		if strings.Contains(fr.Path, "∴") && !strings.HasPrefix(fr.Path, "/") {
			parts := strings.SplitN(fr.Path, " ∴ ", 2)
			if len(parts) >= 1 {
				return strings.TrimSpace(parts[0])
			}
		}
	}
	return ""
}

// ExtractTmpRoot extracts the temporary directory root from paths in a report.
func ExtractTmpRoot(files map[string]*malcontent.FileReport) string {
	for _, fr := range files {
		if fr == nil || fr.Path == "" {
			continue
		}

		if matches := tempDirPattern.FindStringSubmatch(fr.Path); len(matches) > 1 {
			return matches[1]
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

	// Remove temp directory prefix if present
	if tmpRoot != "" && strings.HasPrefix(path, tmpRoot) {
		path = strings.TrimPrefix(path, tmpRoot)
	}

	// Also try to remove any remaining temp dir pattern
	if matches := tempDirPattern.FindStringSubmatch(path); len(matches) > 1 {
		path = strings.TrimPrefix(path, matches[1])
	}

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, imageURI) {
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

	clean := path

	if tmpRoot != "" && strings.HasPrefix(clean, tmpRoot) {
		clean = strings.TrimPrefix(clean, tmpRoot)
	}

	if matches := tempDirPattern.FindStringSubmatch(clean); len(matches) > 1 {
		clean = strings.TrimPrefix(clean, matches[1])
	}

	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}

	if imageURI != "" {
		return imageURI + " ∴ " + clean
	}

	return clean
}
