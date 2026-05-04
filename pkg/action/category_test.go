// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
)

func TestMatchesAnyCategory(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   string
		cats []string
		want bool
	}{
		{"empty cats is no-op", "exfil/stealer/foo", nil, true},
		{"empty slice cats is no-op", "exfil/stealer/foo", []string{}, true},
		{"exact category match", "exfil", []string{"exfil"}, true},
		{"category prefix matches", "exfil/stealer/foo", []string{"exfil"}, true},
		{"deeper category prefix matches", "exfil/stealer/foo", []string{"exfil/stealer"}, true},
		{"non-matching category", "net/http/get", []string{"exfil"}, false},
		{"prefix boundary respected", "exfiltrate/foo", []string{"exfil"}, false},
		{"deeper prefix boundary respected", "exfil/stealerz/foo", []string{"exfil/stealer"}, false},
		{"union of categories: matches second", "net/http/get", []string{"exfil", "net"}, true},
		{"union of categories: matches none", "fs/read", []string{"exfil", "net"}, false},
		{"empty string category never matches", "exfil/foo", []string{""}, false},
		{"empty rule id never matches non-empty cat", "", []string{"exfil"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := MatchesAnyCategory(tt.id, tt.cats); got != tt.want {
				t.Errorf("MatchesAnyCategory(%q, %v) = %v, want %v", tt.id, tt.cats, got, tt.want)
			}
		})
	}
}

func TestFilterBehaviorsByCategory_Empty(t *testing.T) {
	t.Parallel()
	bs := []*malcontent.Behavior{
		{ID: "exfil/stealer/foo"},
		{ID: "net/http/get"},
	}
	got, dropped := FilterBehaviorsByCategory(bs, nil)
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0 for empty cats", dropped)
	}
	if len(got) != len(bs) {
		t.Errorf("len(got) = %d, want %d", len(got), len(bs))
	}
	for i := range bs {
		if got[i] != bs[i] {
			t.Errorf("got[%d] = %v, want %v", i, got[i], bs[i])
		}
	}
}

func TestFilterBehaviorsByCategory_Single(t *testing.T) {
	t.Parallel()
	bs := []*malcontent.Behavior{
		{ID: "exfil/stealer/foo"},
		{ID: "net/http/get"},
		{ID: "exfil/discord"},
	}
	got, dropped := FilterBehaviorsByCategory(bs, []string{"exfil"})
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].ID != "exfil/stealer/foo" || got[1].ID != "exfil/discord" {
		t.Errorf("unexpected ids: %v, %v", got[0].ID, got[1].ID)
	}
}

func TestFilterBehaviorsByCategory_Multiple(t *testing.T) {
	t.Parallel()
	bs := []*malcontent.Behavior{
		{ID: "exfil/stealer/foo"},
		{ID: "net/http/get"},
		{ID: "fs/read/secret"},
	}
	got, dropped := FilterBehaviorsByCategory(bs, []string{"exfil", "net"})
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1", dropped)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
}

func TestFilterBehaviorsByCategory_Unknown(t *testing.T) {
	t.Parallel()
	bs := []*malcontent.Behavior{
		{ID: "exfil/stealer/foo"},
		{ID: "net/http/get"},
	}
	got, dropped := FilterBehaviorsByCategory(bs, []string{"definitely-not-a-category"})
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2", dropped)
	}
	if len(got) != 0 {
		t.Errorf("len(got) = %d, want 0", len(got))
	}
}

func TestFilterBehaviorsByCategory_NeverAdds(t *testing.T) {
	t.Parallel()
	bs := []*malcontent.Behavior{
		{ID: "a/b/c"},
		{ID: "d/e/f"},
		{ID: "g/h/i"},
	}
	for _, cats := range [][]string{
		nil,
		{"a"},
		{"a", "d"},
		{"a", "d", "g"},
		{"nope"},
		{""},
	} {
		got, _ := FilterBehaviorsByCategory(bs, cats)
		if len(got) > len(bs) {
			t.Errorf("filter added behaviors for cats=%v: len(got)=%d > len(in)=%d", cats, len(got), len(bs))
		}
		seen := map[*malcontent.Behavior]bool{}
		for _, b := range bs {
			seen[b] = true
		}
		for _, b := range got {
			if !seen[b] {
				t.Errorf("filter produced behavior not in input for cats=%v", cats)
			}
		}
	}
}

func TestFilterBehaviorsByCategory_PrefixBoundary(t *testing.T) {
	t.Parallel()
	bs := []*malcontent.Behavior{
		{ID: "exfil/stealer/foo"},
		{ID: "exfiltrate/oops"},
	}
	got, _ := FilterBehaviorsByCategory(bs, []string{"exfil"})
	if len(got) != 1 || got[0].ID != "exfil/stealer/foo" {
		t.Errorf("got = %v, want exactly [exfil/stealer/foo]", got)
	}
}

func TestApplyCategoryFilter_DropsEmptyFiles(t *testing.T) {
	t.Parallel()
	files := xsync.NewMap[string, *malcontent.FileReport]()
	files.Store("/a", &malcontent.FileReport{
		Path:      "/a",
		Behaviors: []*malcontent.Behavior{{ID: "net/http/get"}},
	})
	files.Store("/b", &malcontent.FileReport{
		Path:      "/b",
		Behaviors: []*malcontent.Behavior{{ID: "exfil/stealer/foo"}},
	})
	r := &malcontent.Report{Files: files}

	ApplyCategoryFilter(r, []string{"exfil"})

	if _, ok := r.Files.Load("/a"); ok {
		t.Errorf("expected /a to be removed (no exfil behaviors)")
	}
	bRep, ok := r.Files.Load("/b")
	if !ok {
		t.Fatalf("expected /b to remain")
	}
	if len(bRep.Behaviors) != 1 || bRep.Behaviors[0].ID != "exfil/stealer/foo" {
		t.Errorf("/b behaviors = %v, want [exfil/stealer/foo]", bRep.Behaviors)
	}
}

func TestApplyCategoryFilter_PreservesOthers(t *testing.T) {
	t.Parallel()
	files := xsync.NewMap[string, *malcontent.FileReport]()
	files.Store("/x", &malcontent.FileReport{
		Path: "/x",
		Behaviors: []*malcontent.Behavior{
			{ID: "exfil/stealer/foo"},
			{ID: "net/http/get"},
		},
	})
	r := &malcontent.Report{Files: files}

	ApplyCategoryFilter(r, []string{"exfil"})

	xRep, ok := r.Files.Load("/x")
	if !ok {
		t.Fatalf("expected /x to remain")
	}
	if len(xRep.Behaviors) != 1 || xRep.Behaviors[0].ID != "exfil/stealer/foo" {
		t.Errorf("/x behaviors = %v, want only exfil/stealer/foo", xRep.Behaviors)
	}
}

func TestApplyCategoryFilter_NoOpWhenUnset(t *testing.T) {
	t.Parallel()
	files := xsync.NewMap[string, *malcontent.FileReport]()
	files.Store("/x", &malcontent.FileReport{
		Path: "/x",
		Behaviors: []*malcontent.Behavior{
			{ID: "exfil/stealer/foo"},
			{ID: "net/http/get"},
		},
	})
	r := &malcontent.Report{Files: files}

	ApplyCategoryFilter(r, nil)
	ApplyCategoryFilter(r, []string{})

	xRep, ok := r.Files.Load("/x")
	if !ok {
		t.Fatalf("expected /x to remain")
	}
	if len(xRep.Behaviors) != 2 {
		t.Errorf("/x behaviors len = %d, want 2 (unchanged)", len(xRep.Behaviors))
	}
}

func TestTrimFileReport_NoOpWhenUnset(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{
		Path: "/x",
		Behaviors: []*malcontent.Behavior{
			{ID: "exfil/foo"},
			{ID: "net/get"},
		},
	}
	if !TrimFileReport(fr, nil) {
		t.Fatalf("TrimFileReport(nil cats) = false, want true")
	}
	if !TrimFileReport(fr, []string{}) {
		t.Fatalf("TrimFileReport(empty cats) = false, want true")
	}
	if len(fr.Behaviors) != 2 {
		t.Errorf("behaviors mutated by no-op: len=%d, want 2", len(fr.Behaviors))
	}
}

func TestTrimFileReport_TrimsInPlace(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{
		Path: "/x",
		Behaviors: []*malcontent.Behavior{
			{ID: "exfil/foo"},
			{ID: "net/get"},
		},
	}
	if !TrimFileReport(fr, []string{"net"}) {
		t.Fatalf("TrimFileReport = false, want true (one match remains)")
	}
	if len(fr.Behaviors) != 1 || fr.Behaviors[0].ID != "net/get" {
		t.Errorf("behaviors = %v, want [net/get]", fr.Behaviors)
	}
}

func TestTrimFileReport_KeepsFileWhenNoMatch(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{
		Path: "/x",
		Behaviors: []*malcontent.Behavior{
			{ID: "data/foo"},
		},
	}
	if TrimFileReport(fr, []string{"net"}) {
		t.Fatalf("TrimFileReport = true, want false (no match)")
	}
	if fr == nil {
		t.Fatalf("TrimFileReport must not nil out the report")
	}
	if len(fr.Behaviors) != 0 {
		t.Errorf("behaviors = %v, want empty after no-match trim", fr.Behaviors)
	}
}

func TestFilterFileReportByCategory_ComposesWithMinRiskInputs(t *testing.T) {
	t.Parallel()
	bs := []*malcontent.Behavior{
		{ID: "exfil/stealer/foo", RiskScore: 1},
		{ID: "exfil/discord", RiskScore: 4},
		{ID: "net/http/get", RiskScore: 4},
	}
	cat, _ := FilterBehaviorsByCategory(bs, []string{"exfil"})

	highOnly := make([]*malcontent.Behavior, 0, len(cat))
	for _, b := range cat {
		if b.RiskScore >= 3 {
			highOnly = append(highOnly, b)
		}
	}
	if len(highOnly) != 1 || highOnly[0].ID != "exfil/discord" {
		t.Errorf("intersection = %v, want only [exfil/discord]", highOnly)
	}
}
