// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"context"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// maxFuzzSize is the maximum input size for fuzz tests to stay well under
// Go's 100MB fuzzer shared memory capacity and avoid OOM in parsers.
const maxFuzzSize = 10 * 1024 * 1024

// FuzzRemoveRulesExact tests the removeRules function with random inputs.
func FuzzRemoveRulesExact(f *testing.F) {
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
		if len(data) > maxFuzzSize {
			return
		}
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

			if len(data) > maxFuzzSize {
				return nil
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

	// yara[-x] does not support floating-point literals in conditions.
	// The yara-x C API aborts (exit status 2) on inputs like
	// "filesize < 1.485760", which cannot be caught by recover().
	floatPattern := regexp.MustCompile(`\d+\.\d+`)

	f.Fuzz(func(_ *testing.T, data []byte) {
		if len(data) > maxFuzzSize {
			return
		}

		// Skip inputs containing non-printable-ASCII bytes.
		if slices.ContainsFunc(data, func(b byte) bool {
			return b > 0x7e || (b < 0x20 && b != '\n' && b != '\r' && b != '\t')
		}) {
			return
		}

		// Skip inputs with float literals that crash the YARA-X C library.
		if bytes.Contains(data, []byte("condition")) && floatPattern.Match(data) {
			return
		}

		fsys := fstest.MapFS{
			"test.yara": {
				Data: data,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_, _ = Recursive(ctx, []fs.FS{fsys})
	})
}

// FuzzRemoveRulesRegex tests removeRules with adversarial rule names containing
// regex-significant characters to ensure no ReDoS or panics.
func FuzzRemoveRulesRegex(f *testing.F) {
	// Normal rule names
	f.Add([]byte(`rule test_rule { condition: true }`), "test_rule")
	// Regex-significant characters in rule names
	f.Add([]byte(`rule test { condition: true }`), "test.*")
	f.Add([]byte(`rule test { condition: true }`), "test+")
	f.Add([]byte(`rule test { condition: true }`), "test?")
	f.Add([]byte(`rule test { condition: true }`), "(test)")
	f.Add([]byte(`rule test { condition: true }`), "[test]")
	f.Add([]byte(`rule test { condition: true }`), "test{1,2}")
	f.Add([]byte(`rule test { condition: true }`), "test|other")
	f.Add([]byte(`rule test { condition: true }`), `test\d+`)
	f.Add([]byte(`rule test { condition: true }`), "^test$")
	// Multiple rules with special chars
	f.Add([]byte(`rule a { condition: true } rule b { condition: false }`), "a.*,b+")
	// Empty inputs
	f.Add([]byte(``), "")
	f.Add([]byte(`rule x { condition: true }`), "")

	f.Fuzz(func(t *testing.T, data []byte, rulesToRemove string) {
		if len(data) > maxFuzzSize {
			return
		}

		var rules []string
		if rulesToRemove != "" {
			rules = strings.Split(rulesToRemove, ",")
		}

		result := removeRules(data, rules)

		// Result should never be longer than input
		if len(result) > len(data) {
			t.Fatalf("result length %d > input length %d", len(result), len(data))
		}

		// Empty rule list should not modify data
		if len(rules) == 0 || (len(rules) == 1 && rules[0] == "") {
			if string(result) != string(data) {
				t.Error("removeRules with empty rule list modified data")
			}
		}
	})
}
