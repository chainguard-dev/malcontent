// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

// Scope is the file type and path scoping a rule declares in its metadata:
// "filetypes", "path_include", and "path_exclude". Reports keep a match of a
// rule only for files within its scope.
type Scope struct {
	s ruleScope
}

// NewScope returns the scoping declared by meta, which maps each of the
// scoping keys a rule declares to its value.
func NewScope(meta map[string]string) Scope {
	return Scope{s: scopeFromValues(meta)}
}

// ScopeTarget is what a scope is checked against: a file's detected
// extension and its display path, the inputs reports use.
type ScopeTarget struct {
	ext  string
	path string
}

// NewScopeTarget returns the target for the file at path, scanned within
// expath, whose detected kind is kind.
func NewScopeTarget(kind *programkind.FileType, path, expath string, c malcontent.Config) ScopeTarget {
	t := ScopeTarget{path: filepath.ToSlash(trimDisplayPath(path, expath, c))}
	if kind != nil {
		t.ext = kind.Ext
	}
	return t
}

// Applies reports whether a rule with scope s applies to the file t
// describes, which is when reports keep the rule's matches.
func (s Scope) Applies(t ScopeTarget) bool {
	return s.s.matches(t.ext, t.path)
}

// scopeFromValues builds a ruleScope from the values of the scoping keys a
// rule declares.
func scopeFromValues(meta map[string]string) ruleScope {
	var s ruleScope
	var filetypes, include string
	filetypes, s.hasFiletypes = meta["filetypes"]
	include, s.hasInclude = meta["path_include"]
	if s.hasFiletypes {
		s.filetypes = strings.Split(filetypes, ",")
	}
	if s.hasInclude {
		s.include = compileGlobs(include)
		s.includeTypes = strings.Split(globExtensions(include), ",")
	}
	s.exclude = compileGlobs(meta["path_exclude"])
	return s
}
