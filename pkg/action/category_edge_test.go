// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"slices"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// categoryTestIDs returns the IDs of bs in order.
func categoryTestIDs(bs []*malcontent.Behavior) []string {
	ids := make([]string, 0, len(bs))
	for _, b := range bs {
		ids = append(ids, b.ID)
	}
	return ids
}

func TestMatchesAnyCategoryEmptyEntryDoesNotEndTheSearch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   string
		cats []string
		want bool
	}{
		{name: "match after an empty category", id: "exfil/stealer/foo", cats: []string{"", "exfil"}, want: true},
		{name: "no match after an empty category", id: "exfil/stealer/foo", cats: []string{"", "net"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := MatchesAnyCategory(tt.id, tt.cats); got != tt.want {
				t.Errorf("MatchesAnyCategory(%q, %q): got = %v, want = %v", tt.id, tt.cats, got, tt.want)
			}
		})
	}
}

func TestFilterBehaviorsByCategoryIgnoresEmptyCategories(t *testing.T) {
	t.Parallel()
	bs := []*malcontent.Behavior{{ID: "exfil/foo"}, {ID: "net/get"}, {ID: "exfil/bar"}}
	got, dropped := FilterBehaviorsByCategory(bs, []string{"", "exfil"})
	if want := []string{"exfil/foo", "exfil/bar"}; !slices.Equal(categoryTestIDs(got), want) {
		t.Errorf("kept IDs: got = %q, want = %q", categoryTestIDs(got), want)
	}
	if dropped != 1 {
		t.Errorf("dropped: got = %d, want = 1", dropped)
	}
}

func TestTrimFileReportEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		fr           *malcontent.FileReport
		cats         []string
		want         bool
		wantIDs      []string
		wantFiltered int
	}{
		{
			name: "nil report with categories is kept",
			cats: []string{"exfil"},
			want: true,
		},
		{
			name:    "report without behaviors and no categories is kept",
			fr:      &malcontent.FileReport{Path: "/x"},
			want:    true,
			wantIDs: []string{},
		},
		{
			name:    "skipped report is left untouched",
			fr:      &malcontent.FileReport{Path: "/x", Skipped: "zero-sized file", Behaviors: []*malcontent.Behavior{{ID: "net/get"}}},
			cats:    []string{"exfil"},
			want:    true,
			wantIDs: []string{"net/get"},
		},
		{
			name: "dropped behaviors add to the earlier filtered count",
			fr: &malcontent.FileReport{
				Path:              "/x",
				FilteredBehaviors: 2,
				Behaviors:         []*malcontent.Behavior{{ID: "exfil/foo"}, {ID: "net/get"}, {ID: "fs/read"}},
			},
			cats:         []string{"exfil"},
			want:         true,
			wantIDs:      []string{"exfil/foo"},
			wantFiltered: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := TrimFileReport(tt.fr, tt.cats); got != tt.want {
				t.Errorf("TrimFileReport: got = %v, want = %v", got, tt.want)
			}
			if tt.fr == nil {
				return
			}
			if got := categoryTestIDs(tt.fr.Behaviors); !slices.Equal(got, tt.wantIDs) {
				t.Errorf("behavior IDs: got = %q, want = %q", got, tt.wantIDs)
			}
			if tt.fr.FilteredBehaviors != tt.wantFiltered {
				t.Errorf("FilteredBehaviors: got = %d, want = %d", tt.fr.FilteredBehaviors, tt.wantFiltered)
			}
		})
	}
}

func TestApplyCategoryFilterWithoutFiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    *malcontent.Report
	}{
		{name: "nil report", r: nil},
		{name: "report without a file map", r: &malcontent.Report{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ApplyCategoryFilter(tt.r, []string{"exfil"})
			if tt.r != nil && tt.r.Files != nil {
				t.Errorf("Files: got = %v, want nil", tt.r.Files)
			}
		})
	}
}

func TestCategoryMatchingIgnoresEmptyCategories(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   string
		cats []string
		want bool
	}{
		{name: "empty rule ID does not match an empty category", id: "", cats: []string{""}},
		{name: "rule ID with a leading slash does not match an empty category", id: "/exfil/foo", cats: []string{"", "net"}},
		{name: "rule ID equal to a category matches", id: "exfil", cats: []string{"", "exfil"}, want: true},
		{name: "rule ID below a category matches", id: "exfil/foo", cats: []string{"", "exfil"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := MatchesAnyCategory(tt.id, tt.cats); got != tt.want {
				t.Errorf("MatchesAnyCategory(%q, %q): got = %v, want = %v", tt.id, tt.cats, got, tt.want)
			}
			kept, dropped := FilterBehaviorsByCategory([]*malcontent.Behavior{{ID: tt.id}}, tt.cats)
			wantKept := 0
			if tt.want {
				wantKept = 1
			}
			if len(kept) != wantKept || dropped != 1-wantKept {
				t.Errorf("FilterBehaviorsByCategory: got %d kept and %d dropped, want %d kept and %d dropped", len(kept), dropped, wantKept, 1-wantKept)
			}
		})
	}
}
