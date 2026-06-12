// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import "testing"

func TestExtMatchesFiletypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		filetypes string
		ext       string
		want      bool
	}{
		{"exact match against single filetype", "elf", "elf", true},
		{"exact match within filetype list", "jar,java", "java", true},
		{"class verbatim when rule lists class", "class,java", "class", true},
		{"class matches jar scoped rule via alias", "jar", "class", true},
		{"class matches java scoped rule via alias", "java", "class", true},
		{"class matches jar and java scoped rule via alias", "jar,java", "class", true},
		{"no match against unrelated filetypes", "py,elf", "macho", false},
		{"class does not match non java filetypes", "py,elf", "class", false},
		{"jar does not inherit class scoping", "class", "jar", false},
		{"java does not inherit class scoping", "class", "java", false},
		{"empty extension does not match scoped rule", "jar,java", "", false},
		{"java is not a substring match of javascript", "javascript", "java", false},
		{"extension superstring does not match", "jar,java", "jarx", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := extMatchesFiletypes(tt.filetypes, tt.ext); got != tt.want {
				t.Errorf("extMatchesFiletypes(%q, %q) = %v, want %v", tt.filetypes, tt.ext, got, tt.want)
			}
		})
	}
}

func TestFileMatchesRuleUniversal(t *testing.T) {
	t.Parallel()
	// Rules without filetypes metadata apply to every extension.
	for _, ext := range []string{"", "class", "elf", "py"} {
		if !fileMatchesRule(nil, ext) {
			t.Errorf("fileMatchesRule(nil, %q) = false, want true", ext)
		}
	}
}
