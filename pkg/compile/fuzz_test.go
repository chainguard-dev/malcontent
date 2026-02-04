// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// FuzzRemoveRules tests the removeRules function with random inputs.
func FuzzRemoveRules(f *testing.F) {
	for _, root := range getAllRuleFS() {
		err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}

			if !strings.HasSuffix(path, ".yara") && !strings.HasSuffix(path, ".yar") {
				return nil
			}

			data, err := fs.ReadFile(root, path)
			if err != nil {
				return err
			}

			ruleNamePattern := `rule\s+(\w+)`
			re := regexp.MustCompile(ruleNamePattern)
			matches := re.FindAllStringSubmatch(string(data), -1)

			if len(matches) > 0 {
				ruleName := matches[0][1]
				f.Add(data, ruleName)

				if len(matches) > 1 {
					var ruleNames []string
					for _, m := range matches[:min(5, len(matches))] {
						ruleNames = append(ruleNames, m[1])
					}
					f.Add(data, strings.Join(ruleNames, ","))
				}
			}

			return nil
		})
		if err != nil {
			f.Logf("failed to walk rules directory: %v", err)
		}
	}

	// Edge cases
	f.Add([]byte(``), "")
	f.Add([]byte(`rule empty {}`), "empty")
	f.Add([]byte(`not a valid rule`), "anything")

	// Complex rule names with special characters
	f.Add([]byte(`rule test_123 { condition: true }`), "test_123")
	f.Add([]byte(`rule Test_Rule { condition: true }`), "Test_Rule")

	// Non-UTF8 rule name (should be skipped)
	f.Add([]byte(`rule test { condition: true }`), "\xff\xfe")

	// Multiple rules to remove
	f.Add([]byte(`
rule remove_me_1 { condition: true }
rule remove_me_2 { condition: false }
rule keep_me { condition: true }
`), "remove_me_1,remove_me_2")

	f.Fuzz(func(t *testing.T, data []byte, rulesToRemove string) {
		var rules []string
		if rulesToRemove != "" {
			rules = strings.Split(rulesToRemove, ",")
		}

		result := removeRules(data, rules)

		if len(result) > len(data) {
			t.Fatalf("result length %d > input length %d", len(result), len(data))
		}

		if len(rules) == 0 || (len(rules) == 1 && rules[0] == "") {
			if string(result) != string(data) {
				t.Error("removeRules with empty rule list modified data")
			}
		}
	})
}

// FuzzRecursiveCompile tests the Recursive compilation function with real YARA rules.
func FuzzRecursiveCompile(f *testing.F) {
	for _, root := range getAllRuleFS() {
		err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}

			if !strings.HasSuffix(path, ".yara") && !strings.HasSuffix(path, ".yar") {
				return nil
			}

			data, err := fs.ReadFile(root, path)
			if err != nil {
				return err
			}

			f.Add(data)

			return nil
		})
		if err != nil {
			f.Logf("failed to walk rules directory: %v", err)
		}
	}

	// Edge cases
	f.Add([]byte(``))
	f.Add([]byte(`rule empty {}`))
	f.Add([]byte(`not a valid rule`))

	// Complex rule names with special characters
	f.Add([]byte(`rule test_123 { condition: true }`))
	f.Add([]byte(`rule Test_Rule { condition: true }`))

	// Non-UTF8 rule name (should be skipped)
	f.Add([]byte(`rule \xff\xfe { condition: true }`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		fsys := fstest.MapFS{
			"test.yara": {
				Data: data,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		_, _ = Recursive(ctx, []fs.FS{fsys})
	})
}
