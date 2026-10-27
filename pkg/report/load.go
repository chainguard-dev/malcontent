// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"go.yaml.in/yaml/v3"
)

// tempDirPattern matches the temporary directory root at the start of a path
// extracted under macOS or /tmp.
var tempDirPattern = regexp.MustCompile(`^/(?:var/folders|tmp|private/var/folders|private/tmp)/[^/]+/[^/]+/T/[^/]+`)

// maxEntryKeys bounds the keys of each mapping within a file report of a
// YAML report. The YAML decoder compares every pair of keys in a mapping, and
// the largest mapping the renderer writes, a file report, has fewer than 30.
const maxEntryKeys = 64

var (
	errDiffReport = errors.New("report holds a diff, not scanned files")
	errNoFiles    = errors.New("report holds no scanned files")
)

// Load parses a report written by the JSON or YAML renderer. Input that
// starts with "{" is JSON; other input is YAML, whose syntax errors are
// returned, and input that is neither keeps the JSON error. A report holds
// its files unless it is empty or holds only statistics; a diff report is not
// one. A damaged report, such as one with an empty entry or an unknown risk
// score, returns an error naming the entry. Load clears the diff marks of the
// behaviors it returns.
func Load(data []byte) (malcontent.ScanResult, error) {
	// Some editors start a UTF-8 file with a byte order mark.
	data = bytes.TrimPrefix(data, []byte("\ufeff"))
	load := loadYAML
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '{' {
		load = loadJSON
	}
	files, err := load(data)
	if err == nil {
		err = validate(files)
	}
	if err != nil {
		return malcontent.ScanResult{}, err
	}
	return malcontent.ScanResult{FileReports: files}, nil
}

// loadJSON returns the files of a JSON report.
func loadJSON(data []byte) (map[string]*malcontent.FileReport, error) {
	var doc struct {
		// A diff alone rejects the report, so it stays undecoded.
		Diff  *json.RawMessage
		Files map[string]*malcontent.FileReport
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Diff != nil {
		return nil, errDiffReport
	}
	if doc.Files != nil {
		return doc.Files, nil
	}
	// Without files, the report must be empty or hold only statistics, as the
	// renderer writes for a scan that found nothing. Member names match
	// regardless of case, as they do when decoding.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, err
	}
	for name := range members {
		if !strings.EqualFold(name, "Stats") {
			return nil, errNoFiles
		}
	}
	return nil, nil
}

// loadYAML returns the files of a YAML report. It walks the parsed document
// instead of decoding it whole, because the decoder compares every pair of
// keys in a mapping, which takes time quadratic in the number of files.
func loadYAML(data []byte) (map[string]*malcontent.FileReport, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, notReport(data)
	}

	var files *yaml.Node
	onlyStats := true
	top := doc.Content[0]
	seen := make(map[string]struct{}, len(top.Content)/2)
	for kv := range slices.Chunk(top.Content, 2) {
		k, v := kv[0], kv[1]
		if k.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("line %d: report keys must be scalars", k.Line)
		}
		if _, dup := seen[k.Value]; dup {
			return nil, fmt.Errorf("line %d: report key %q is defined more than once", k.Line, k.Value)
		}
		seen[k.Value] = struct{}{}
		switch {
		case k.Value == "diff" && !isNull(v):
			return nil, errDiffReport
		case k.Value == "files" && !isNull(v):
			files = v
		case k.Value != "stats":
			onlyStats = false
		}
	}
	switch {
	case files != nil:
		return loadYAMLFiles(files)
	case onlyStats:
		return nil, nil
	default:
		return nil, errNoFiles
	}
}

// loadYAMLFiles decodes the entries of n, the files mapping of a YAML report,
// one at a time. It first checks that no key repeats and that each entry
// holds no alias, which could expand it beyond the size of the input, and no
// mapping too large to decode quickly.
func loadYAMLFiles(n *yaml.Node) (map[string]*malcontent.FileReport, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: files is not a mapping", n.Line)
	}
	files := make(map[string]*malcontent.FileReport, len(n.Content)/2)
	var stack []*yaml.Node
	for kv := range slices.Chunk(n.Content, 2) {
		// A key is its text. The renderer writes a file named "<<" unquoted,
		// so here it names that file rather than a merge.
		k, v := kv[0], kv[1]
		if k.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("line %d: report entry keys must be scalars", k.Line)
		}
		if _, dup := files[k.Value]; dup {
			return nil, fmt.Errorf("report entry %q is defined more than once", k.Value)
		}
		var err error
		if stack, err = checkEntry(v, stack[:0]); err != nil {
			return nil, fmt.Errorf("report entry %q: %w", k.Value, err)
		}
		var fr *malcontent.FileReport
		if err := v.Decode(&fr); err != nil {
			return nil, fmt.Errorf("report entry %q: %w", k.Value, err)
		}
		files[k.Value] = fr
	}
	return files, nil
}

// checkEntry returns an error if the tree below n holds an alias or a
// mapping with more than maxEntryKeys keys. It walks the tree with stack and
// returns it for reuse.
func checkEntry(n *yaml.Node, stack []*yaml.Node) ([]*yaml.Node, error) {
	stack = append(stack, n)
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch {
		case n.Kind == yaml.AliasNode:
			return stack, fmt.Errorf("line %d: aliases are not supported", n.Line)
		case n.Kind == yaml.MappingNode && len(n.Content) > 2*maxEntryKeys:
			return stack, fmt.Errorf("line %d: mapping holds more than %d keys", n.Line, maxEntryKeys)
		}
		stack = append(stack, n.Content...)
	}
	return stack, nil
}

// isNull reports whether n is a YAML null.
func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

// notReport returns the error for input that is neither a JSON object nor a
// YAML mapping: the JSON syntax error, which best describes text that is not
// a report, or errNoFiles for another JSON value.
func notReport(data []byte) error {
	if err := json.Unmarshal(data, new(json.RawMessage)); err != nil {
		return err
	}
	return errNoFiles
}

// validate returns the error of the first damaged entry, by key, and clears
// the diff marks of every behavior, which only a diff sets.
func validate(files map[string]*malcontent.FileReport) error {
	bad := map[string]error{}
	for k, fr := range files {
		if err := checkReport(k, fr); err != nil {
			bad[k] = err
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return bad[slices.Min(slices.Collect(maps.Keys(bad)))]
}

// checkReport returns an error if fr, the entry for key, is empty or holds an
// empty behavior, a non-finite score, or an unknown risk score. It clears the
// diff marks of fr's behaviors. An entry's path may differ from its key: a
// renderer that disambiguates colliding keys keeps each entry's own path.
func checkReport(key string, fr *malcontent.FileReport) error {
	switch {
	case fr == nil:
		return fmt.Errorf("report entry %q is empty", key)
	case slices.Contains(fr.Behaviors, nil):
		return fmt.Errorf("report entry %q has an empty behavior", key)
	case math.IsNaN(fr.PreviousRelPathScore) || math.IsInf(fr.PreviousRelPathScore, 0):
		return fmt.Errorf("report entry %q has non-finite previous path score %v", key, fr.PreviousRelPathScore)
	case !knownRisk(fr.RiskScore):
		return fmt.Errorf("report entry %q has unknown risk score %d", key, fr.RiskScore)
	case !knownRisk(fr.PreviousRiskScore):
		return fmt.Errorf("report entry %q has unknown previous risk score %d", key, fr.PreviousRiskScore)
	}
	return cmp.Or(checkBehaviors(key, "behavior", fr.Behaviors), checkBehaviors(key, "override", fr.Overrides))
}

// checkBehaviors returns an error naming the first of bs, the behaviors of
// a kind held by the entry for key, with an unknown risk score. It clears
// their diff marks and skips empty ones.
func checkBehaviors(key, kind string, bs []*malcontent.Behavior) error {
	for _, b := range bs {
		if b == nil {
			continue
		}
		if !knownRisk(b.RiskScore) {
			return fmt.Errorf("report entry %q has %s %q with unknown risk score %d", key, kind, b.ID, b.RiskScore)
		}
		b.DiffAdded, b.DiffRemoved = false, false
	}
	return nil
}

// knownRisk reports whether score is a risk level a report can hold: any of
// RiskLevels but INVALID, which a scan never assigns.
func knownRisk(score int) bool {
	_, ok := RiskLevels[score]
	return ok && score != INVALID
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

// trimRoot removes root from the start of path when root names path or one
// of its parent directories, so that a root never cuts a name short.
func trimRoot(path, root string) string {
	rest, ok := strings.CutPrefix(path, root)
	if ok && (rest == "" || rest[0] == '/' || strings.HasSuffix(root, "/")) {
		return rest
	}
	return path
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
	path = trimRoot(path, tmpRoot)
	path = trimRoot(path, tempDirPattern.FindString(path))

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

	clean := trimRoot(path, tmpRoot)
	clean = trimRoot(clean, tempDirPattern.FindString(clean))

	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}

	if imageURI != "" {
		return imageURI + " ∴ " + clean
	}

	return clean
}
