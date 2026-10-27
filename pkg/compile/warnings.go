// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"cmp"
	"slices"

	yarax "github.com/VirusTotal/yara-x/go"
)

// ruleWarning is a yara-x compiler warning and the rule it concerns.
type ruleWarning struct {
	code   string
	title  string
	origin string
	line   int
	rule   string
}

// ruleStart is the line on which a rule's declaration begins.
type ruleStart struct {
	line int
	name string
}

// attributeWarnings names the rule each warning concerns. source returns the
// text compiled under an origin, or nil when it is unknown, and is called once
// per origin that has warnings.
func attributeWarnings(ws []yarax.Warning, source func(origin string) []byte) []ruleWarning {
	out := make([]ruleWarning, 0, len(ws))
	starts := map[string][]ruleStart{}
	for _, w := range ws {
		rw := ruleWarning{code: w.Code, title: w.Title, line: w.Line}
		if len(w.Labels) > 0 {
			rw.origin = w.Labels[0].CodeOrigin
		}
		s, ok := starts[rw.origin]
		if !ok {
			s = ruleStarts(source(rw.origin))
			starts[rw.origin] = s
		}
		rw.rule = ruleAt(s, rw.line)
		out = append(out, rw)
	}
	return out
}

// ruleStarts lists the line of each rule declaration in src, in order.
func ruleStarts(src []byte) []ruleStart {
	matches := ruleStartRE.FindAllSubmatchIndex(src, -1)
	out := make([]ruleStart, 0, len(matches))
	line, pos := 1, 0
	for _, m := range matches {
		line += bytes.Count(src[pos:m[0]], []byte("\n"))
		pos = m[0]
		out = append(out, ruleStart{line: line, name: string(src[m[4]:m[5]])})
	}
	return out
}

// ruleAt returns the name of the last rule declared on or before line, or ""
// when none is.
func ruleAt(starts []ruleStart, line int) string {
	i, found := slices.BinarySearchFunc(starts, line, func(s ruleStart, l int) int { return cmp.Compare(s.line, l) })
	if found {
		return starts[i].name
	}
	if i == 0 {
		return ""
	}
	return starts[i-1].name
}

// logRuleWarnings logs, at debug level, each warning whose rule allow does
// not permit to have warnings. Warnings never stop compilation: they flag
// rules worth fixing, such as conditions that can never hold.
func logRuleWarnings(ws []ruleWarning, allow map[string]bool) {
	for _, w := range ws {
		if allow[w.rule] {
			continue
		}
		logDebug("Rule compile warning", "code", w.code, "rule", w.rule, "file", w.origin, "line", w.line, "warning", w.title)
	}
}
