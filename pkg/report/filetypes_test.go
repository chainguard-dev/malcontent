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
	// Rules without filetypes/path metadata apply to every extension.
	for _, ext := range []string{"", "class", "elf", "py"} {
		if !fileMatchesRule(nil, ext, "some/path."+ext) {
			t.Errorf("fileMatchesRule(nil, %q) = false, want true", ext)
		}
	}
}

func TestPathMatchesGlobs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		patterns string
		path     string
		want     bool
	}{
		// Extension globs (the common third-party path_include case).
		{"py extension matches nested path", "*.py,*.pyx,*.pyi,*.pth", "/tmp/x/evil.py", true},
		{"py extension matches bare basename", "*.py", "evil.py", true},
		{"py extension does not match txt", "*.py,*.pyx", "/tmp/x/evil.txt", false},
		{"js among many extensions", "*.py,*.js,*.ts,*.mjs", "pkg/index.mjs", true},
		// Filename globs.
		{"package.json anywhere", "*/package.json,package.json", "/tmp/pkg/package.json", true},
		{"bare package.json basename", "package.json", "package.json", true},
		{"setup.py via star-slash", "*/setup.py", "proj/setup.py", true},
		{"setup.py not a suffix of mysetup.py", "setup.py", "proj/mysetup.py", false},
		{"Rakefile exact basename", "extconf.rb,*/extconf.rb,Rakefile,*/Rakefile", "gem/Rakefile", true},
		// Directory-prefix globs (path_exclude usage).
		{"dist directory excluded", "dist/*,build/*,vendor/*,node_modules/*", "/repo/dist/app.js", true},
		{"node_modules nested", "node_modules/*", "/repo/node_modules/pkg/index.js", true},
		{"not in excluded dir", "dist/*,build/*", "/repo/src/app.js", false},
		// Case-insensitive extension matching.
		{"uppercase extension still matches", "*.js", "/repo/Evil.JS", true},
		{"mixed-case filename still matches", "setup.py", "/proj/SETUP.PY", true},
		// Edge cases.
		{"empty pattern list never matches", "", "/repo/app.py", false},
		{"whitespace around patterns tolerated", " *.py , *.go ", "/repo/main.go", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pathMatchesGlobs(tt.patterns, tt.path); got != tt.want {
				t.Errorf("pathMatchesGlobs(%q, %q) = %v, want %v", tt.patterns, tt.path, got, tt.want)
			}
		})
	}
}

func TestGlobExtensions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		patterns string
		want     string
	}{
		{"plain extension globs", "*.py,*.pyx,*.pyi", "py,pyx,pyi"},
		{"path-shaped globs ignored", "*/package.json,package.json,dist/*", ""},
		{"mixed extracts only bare extensions", "*.py,*/setup.py,*.go", "py,go"},
		{"whitespace tolerated", " *.js , *.ts ", "js,ts"},
		{"empty input", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := globExtensions(tt.patterns); got != tt.want {
				t.Errorf("globExtensions(%q) = %q, want %q", tt.patterns, got, tt.want)
			}
		})
	}
}
