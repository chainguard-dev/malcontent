// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

func TestSimpleFullWritesCountsInDecimal(t *testing.T) {
	t.Parallel()
	behaviors := make([]*malcontent.Behavior, 0, 20)
	var want strings.Builder
	want.WriteString("*** changed (10 added, 10 removed): /mod/big\n")
	for i := range 10 {
		behaviors = append(behaviors,
			&malcontent.Behavior{ID: fmt.Sprintf("add/%d", i), DiffAdded: true},
			&malcontent.Behavior{ID: fmt.Sprintf("rem/%d", i), DiffRemoved: true},
		)
		fmt.Fprintf(&want, "+add/%d\n-rem/%d\n", i, i)
	}
	rep := &malcontent.Report{Diff: renderDiff(nil, nil, []*malcontent.FileReport{{Path: "/mod/big", Behaviors: behaviors}})}

	var buf bytes.Buffer
	if err := NewSimple(&buf).Full(t.Context(), &malcontent.Config{}, rep); err != nil {
		t.Fatalf("Full: got err = %v, want = nil", err)
	}
	if got := buf.String(); got != want.String() {
		t.Errorf("Full output:\ngot  = %q\nwant = %q", got, want.String())
	}
}

func TestSimpleFileListsBehaviorsWithLowercaseRisk(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{
		Path:      "/bin/evil",
		RiskScore: 3,
		RiskLevel: report.LevelHIGH,
		Behaviors: []*malcontent.Behavior{
			{ID: "net/connect", RiskScore: 3, RiskLevel: report.LevelHIGH},
			{ID: "fs/read", RiskScore: 2, RiskLevel: report.LevelMEDIUM},
		},
	}
	want := "# /bin/evil: high\nnet/connect: high\nfs/read: medium\n"

	var buf bytes.Buffer
	if err := NewSimple(&buf).File(t.Context(), fr); err != nil {
		t.Fatalf("File: got err = %v, want = nil", err)
	}
	if got := buf.String(); got != want {
		t.Errorf("File output:\ngot  = %q\nwant = %q", got, want)
	}
}

func TestSimpleFullListsChangedBehaviors(t *testing.T) {
	t.Parallel()
	rep := &malcontent.Report{Diff: renderDiff(
		[]*malcontent.FileReport{
			{Path: "/old/empty"},
			{Path: "/old/tool", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}, {ID: "fs/read"}}},
		},
		[]*malcontent.FileReport{
			{Path: "/new/empty"},
			{Path: "/new/tool", Behaviors: []*malcontent.Behavior{{ID: "exec/shell"}}},
		},
		[]*malcontent.FileReport{
			{Path: "/mod/empty"},
			{Path: "/mod/same", Behaviors: []*malcontent.Behavior{{ID: "net/bind"}}},
			{Path: "/mod/changed", Behaviors: []*malcontent.Behavior{
				{ID: "net/bind"},
				{ID: "fs/write", DiffAdded: true},
				{ID: "fs/read", DiffRemoved: true},
			}},
			{Path: "/mod/new-name", PreviousPath: "/mod/old-name", Behaviors: []*malcontent.Behavior{
				{ID: "exec/shell", DiffAdded: true},
			}},
			{Path: "/mod/pruned", Behaviors: []*malcontent.Behavior{
				{ID: "os/env", DiffRemoved: true},
			}},
		},
	)}
	want := "--- missing: /old/tool\n-net/connect\n-fs/read\n" +
		"+++ added: /new/tool\n+exec/shell\n" +
		"*** changed (1 added, 1 removed): /mod/changed\n+fs/write\n-fs/read\n" +
		">>> moved (1 added, 0 removed): /mod/old-name -> /mod/new-name\n+exec/shell\n" +
		"*** changed (0 added, 1 removed): /mod/pruned\n-os/env\n"

	var buf bytes.Buffer
	if err := NewSimple(&buf).Full(t.Context(), &malcontent.Config{}, rep); err != nil {
		t.Fatalf("Full: got err = %v, want = nil", err)
	}
	if got := buf.String(); got != want {
		t.Errorf("Full output:\ngot  = %q\nwant = %q", got, want)
	}
}
