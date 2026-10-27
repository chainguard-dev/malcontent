// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

// MatchesAnyCategory reports whether ruleID matches any of the supplied
// categories. A category matches when it is equal to ruleID or is a
// '/'-bounded prefix of it (so "exfil" matches "exfil/stealer/foo" but
// not "exfiltrate/foo"). An empty or nil categories slice is a no-op
// (returns true) so the filter is opt-in.
func MatchesAnyCategory(ruleID string, categories []string) bool {
	if len(categories) == 0 {
		return true
	}
	for _, c := range categories {
		if c == "" {
			continue
		}
		if ruleID == c || strings.HasPrefix(ruleID, c+"/") {
			return true
		}
	}
	return false
}

// FilterBehaviorsByCategory returns the subset of behaviors whose ID
// matches any of the supplied categories, plus the count of dropped
// entries. Empty/nil categories returns the input slice unchanged.
func FilterBehaviorsByCategory(behaviors []*malcontent.Behavior, categories []string) ([]*malcontent.Behavior, int) {
	if len(categories) == 0 {
		return behaviors, 0
	}
	prefixes := buildCategoryPrefixes(categories)
	kept := make([]*malcontent.Behavior, 0, len(behaviors))
	dropped := 0
	for _, b := range behaviors {
		if b == nil {
			continue
		}
		if matchesPrefixes(b.ID, prefixes) {
			kept = append(kept, b)
		} else {
			dropped++
		}
	}
	return kept, dropped
}

// trimFileReportBehaviors applies the category filter to one FileReport
// in place, and rescores it from the behaviors it keeps. It never drops the
// report itself; callers that want empty reports removed must do so
// explicitly. Returns false only when the report ended up with zero matching
// behaviors.
func trimFileReportBehaviors(fr *malcontent.FileReport, categories []string) bool {
	if fr == nil || len(categories) == 0 {
		return true
	}
	if fr.Skipped != "" {
		return true
	}
	all := fr.Behaviors
	kept, dropped := FilterBehaviorsByCategory(all, categories)
	fr.Behaviors = kept
	fr.FilteredBehaviors += dropped
	if dropped > 0 {
		rescore(fr, all)
	}
	return len(kept) > 0
}

// rescore sets the risk of fr, whose behaviors a filter cut down from all,
// from the behaviors it keeps: the highest of their risks. A file that
// report generation raised above its highest behavior, to CRITICAL for its
// many HIGH behaviors, keeps that risk only while the filter kept every
// behavior of HIGH risk or above that the raise counted.
func rescore(fr *malcontent.FileReport, all []*malcontent.Behavior) {
	highest := func(bs []*malcontent.Behavior) int {
		risk := 0
		for _, b := range bs {
			if b != nil {
				risk = max(risk, b.RiskScore)
			}
		}
		return risk
	}
	high := func(bs []*malcontent.Behavior) int {
		n := 0
		for _, b := range bs {
			if b != nil && b.RiskScore >= report.HIGH {
				n++
			}
		}
		return n
	}
	raised := fr.RiskScore > highest(all)
	if !raised || high(fr.Behaviors) != high(all) {
		fr.RiskScore = highest(fr.Behaviors)
	}
	fr.RiskLevel = report.RiskLevels[fr.RiskScore]
}

// TrimFileReport trims behaviors on a single FileReport to those matching
// any of the categories. Returns true when at least one behavior remains
// (useful for callers that want to skip rendering empty reports). Empty/nil
// categories is a no-op (returns true).
func TrimFileReport(fr *malcontent.FileReport, categories []string) bool {
	return trimFileReportBehaviors(fr, categories)
}

// ApplyCategoryFilter trims each FileReport in the report so that only
// behaviors matching one of the categories remain, then removes any
// FileReport whose behavior list became empty. Empty/nil categories is
// a no-op. Use this for analyze/scan output where empty entries are
// noise — for the diff path, prefer TrimFileReport per-file so that
// reconciliation can still see both sides of a change.
func ApplyCategoryFilter(r *malcontent.Report, categories []string) {
	if r == nil || r.Files == nil || len(categories) == 0 {
		return
	}
	r.Files.Range(func(key string, fr *malcontent.FileReport) bool {
		if !trimFileReportBehaviors(fr, categories) {
			r.Files.Delete(key)
		}
		return true
	})
}

// categoryPrefix is "<cat>/" and exact is "<cat>" for each non-empty
// category, hoisted out of the inner loop to avoid repeated allocation.
type categoryPrefix struct {
	exact, withSlash string
}

func buildCategoryPrefixes(categories []string) []categoryPrefix {
	out := make([]categoryPrefix, 0, len(categories))
	for _, c := range categories {
		if c == "" {
			continue
		}
		out = append(out, categoryPrefix{exact: c, withSlash: c + "/"})
	}
	return out
}

func matchesPrefixes(ruleID string, prefixes []categoryPrefix) bool {
	for _, p := range prefixes {
		if ruleID == p.exact || strings.HasPrefix(ruleID, p.withSlash) {
			return true
		}
	}
	return false
}
