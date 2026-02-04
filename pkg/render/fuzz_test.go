// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	orderedmap "github.com/wk8/go-ordered-map/v2"
	"gopkg.in/yaml.v3"
)

// FuzzRenderDifferential ensures JSON and YAML renderers produce semantically equivalent output.
func FuzzRenderDifferential(f *testing.F) {
	f.Add(int8(0), "/bin/ls", "test_behavior", "description", false)
	f.Add(int8(1), "/usr/bin/curl", "net/http", "HTTP client", false)
	f.Add(int8(2), "/tmp/test", "file/write", "Writes files", false)
	f.Add(int8(3), "/opt/app", "exec/shell", "Executes commands", false)
	f.Add(int8(4), "/sbin/daemon", "proc/fork", "Forks processes", false)
	f.Add(int8(2), "", "", "", false) // Empty strings
	f.Add(int8(1), "/path/with spaces", "behavior", "desc", false)
	f.Add(int8(3), "/path/with/unicode/世界", "test", "测试", false)
	f.Add(int8(2), "/path/with\"quotes'", "behave", "desc", false)
	f.Add(int8(1), "/path/with\nnewline", "test", "multiline\ndesc", false)
	f.Add(int8(0), "/very/long/"+strings.Repeat("path/", 50), "behavior", "description", false)
	f.Add(int8(4), "/bin/app", "critical", "Very dangerous", true) // With diff

	f.Fuzz(func(t *testing.T, riskLevel int8, filePath, behaviorName, behaviorDesc string, hasDiff bool) {
		if filePath == "" {
			return
		}

		risk := max(int(riskLevel)%5, 0)

		report := &malcontent.Report{
			Files: sync.Map{},
		}

		fileReport := &malcontent.FileReport{
			Path:      filePath,
			RiskScore: risk,
			RiskLevel: riskLevelString(risk),
		}

		if behaviorName != "" {
			fileReport.Behaviors = []*malcontent.Behavior{
				{
					ID:          behaviorName,
					Description: behaviorDesc,
					RiskScore:   risk,
				},
			}
		}

		report.Files.Store(filePath, fileReport)

		if hasDiff {
			report.Diff = &malcontent.DiffReport{
				Added:    orderedmap.New[string, *malcontent.FileReport](),
				Removed:  orderedmap.New[string, *malcontent.FileReport](),
				Modified: orderedmap.New[string, *malcontent.FileReport](),
			}
		}

		ctx := context.Background()
		cfg := &malcontent.Config{Stats: !hasDiff} // Stats only when no diff

		var jsonBuf bytes.Buffer
		jsonRenderer := NewJSON(&jsonBuf)
		if err := jsonRenderer.Full(ctx, cfg, report); err != nil {
			return
		}

		var yamlBuf bytes.Buffer
		yamlRenderer := NewYAML(&yamlBuf)
		if err := yamlRenderer.Full(ctx, cfg, report); err != nil {
			t.Fatalf("YAML rendering failed but JSON succeeded: %v", err)
		}

		var fromJSON, fromYAML Report

		if err := json.Unmarshal(jsonBuf.Bytes(), &fromJSON); err != nil {
			t.Fatalf("JSON unmarshal failed: %v\nJSON: %s", err, jsonBuf.String())
		}

		if err := yaml.Unmarshal(yamlBuf.Bytes(), &fromYAML); err != nil {
			t.Fatalf("YAML unmarshal failed: %v\nYAML: %s", err, yamlBuf.String())
		}

		if len(fromJSON.Files) != len(fromYAML.Files) {
			t.Errorf("File count mismatch: JSON=%d YAML=%d", len(fromJSON.Files), len(fromYAML.Files))
		}

		for key, jsonFR := range fromJSON.Files {
			yamlFR, ok := fromYAML.Files[key]
			if !ok {
				t.Errorf("File %q present in JSON but missing in YAML", key)
				continue
			}

			if jsonFR.Path != yamlFR.Path {
				t.Errorf("Path mismatch for %q: JSON=%q YAML=%q", key, jsonFR.Path, yamlFR.Path)
			}

			if jsonFR.RiskScore != yamlFR.RiskScore {
				t.Errorf("RiskScore mismatch for %q: JSON=%d YAML=%d", key, jsonFR.RiskScore, yamlFR.RiskScore)
			}

			if jsonFR.RiskLevel != yamlFR.RiskLevel {
				t.Errorf("RiskLevel mismatch for %q: JSON=%q YAML=%q", key, jsonFR.RiskLevel, yamlFR.RiskLevel)
			}

			if len(jsonFR.Behaviors) != len(yamlFR.Behaviors) {
				t.Errorf("Behavior count mismatch for %q: JSON=%d YAML=%d",
					key, len(jsonFR.Behaviors), len(yamlFR.Behaviors))
			}
		}

		compareDiffReports(t, fromJSON.Diff, fromYAML.Diff)

		if (fromJSON.Stats == nil) != (fromYAML.Stats == nil) {
			t.Errorf("Stats presence mismatch: JSON nil=%v, YAML nil=%v",
				fromJSON.Stats == nil, fromYAML.Stats == nil)
		}
	})
}

func riskLevelString(risk int) string {
	switch risk {
	case 0, 1:
		return "low"
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	default:
		return "unknown"
	}
}

// compareDiffReports compares two diff reports for equality.
func compareDiffReports(t *testing.T, jsonDiff, yamlDiff *malcontent.DiffReport) {
	t.Helper()

	if jsonDiff == nil && yamlDiff == nil {
		return
	}

	if (jsonDiff == nil) != (yamlDiff == nil) {
		t.Errorf("Diff presence mismatch: JSON nil=%v, YAML nil=%v",
			jsonDiff == nil, yamlDiff == nil)
		return
	}

	jsonAddedLen := orderedMapLen(jsonDiff.Added)
	yamlAddedLen := orderedMapLen(yamlDiff.Added)
	jsonRemovedLen := orderedMapLen(jsonDiff.Removed)
	yamlRemovedLen := orderedMapLen(yamlDiff.Removed)
	jsonModifiedLen := orderedMapLen(jsonDiff.Modified)
	yamlModifiedLen := orderedMapLen(yamlDiff.Modified)

	if jsonAddedLen != yamlAddedLen {
		t.Errorf("Diff Added count mismatch: JSON=%d YAML=%d", jsonAddedLen, yamlAddedLen)
	}
	if jsonRemovedLen != yamlRemovedLen {
		t.Errorf("Diff Removed count mismatch: JSON=%d YAML=%d", jsonRemovedLen, yamlRemovedLen)
	}
	if jsonModifiedLen != yamlModifiedLen {
		t.Errorf("Diff Modified count mismatch: JSON=%d YAML=%d", jsonModifiedLen, yamlModifiedLen)
	}
}

// orderedMapLen returns the length of an ordered map, or 0 if nil.
func orderedMapLen[K comparable, V any](m *orderedmap.OrderedMap[K, V]) int {
	if m == nil {
		return 0
	}
	return m.Len()
}
