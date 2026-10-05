// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

// markdownCountdownCtx stays live for the first allowed calls to Err and
// reports cancellation afterward, so a later cancellation check can fail
// after an earlier one passed.
type markdownCountdownCtx struct {
	context.Context
	allowed int
	calls   int
}

func (c *markdownCountdownCtx) Err() error {
	c.calls++
	if c.calls > c.allowed {
		return context.Canceled
	}
	return nil
}

func TestMarkdownFile(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{
		Path:      "/bin/evil",
		RiskScore: 3,
		RiskLevel: report.LevelHIGH,
		Behaviors: []*malcontent.Behavior{
			{ID: "fs/read", Description: "reads files", RiskScore: 1, RiskLevel: report.LevelLOW, RuleURL: "https://rules.example/read", RuleAuthor: "Alice", RuleAuthorURL: "https://alice.example"},
			{ID: "net/connect", Description: "connects to hosts. Uses raw sockets", RiskScore: 3, RiskLevel: report.LevelHIGH, RuleURL: "https://rules.example/connect", ReferenceURL: "https://ref.example/connect", MatchStrings: []string{"AF_INET"}},
			{ID: "exec/shell", RiskScore: 2, RiskLevel: report.LevelMEDIUM, RuleURL: "https://rules.example/shell", RuleAuthor: "Bob", MatchStrings: []string{"$sh", "/bin/sh"}},
		},
	}

	var buf bytes.Buffer
	if err := NewMarkdown(&buf).File(t.Context(), fr); err != nil {
		t.Fatalf("File: got err = %v, want = nil", err)
	}
	got := buf.String()

	if want := "## /bin/evil [" + riskEmoji(3) + " HIGH]\n\n"; !strings.HasPrefix(got, want) {
		t.Errorf("File title: got = %q, want prefix %q", got, want)
	}
	// Rows sort by descending risk; descriptions keep their first sentence and link references and authors.
	rows := []string{
		"| RISK | KEY | DESCRIPTION | EVIDENCE |",
		"| HIGH | [net/connect](https://rules.example/connect) | [connects to hosts](https://ref.example/connect) | [AF\\_INET](https://github.com/search?q=AF_INET&type=code) |",
		"| MEDIUM | [exec/shell](https://rules.example/shell) | by Bob | `$sh`<br>[/bin/sh](https://github.com/search?q=%2Fbin%2Fsh&type=code) |",
		"| LOW | [fs/read](https://rules.example/read) | reads files, by [Alice](https://alice.example) |",
	}
	if !renderIndexOrder(got, rows...) {
		t.Errorf("File rows: got = %q, want rows in order %q", got, rows)
	}
	if strings.Contains(got, "raw sockets") {
		t.Errorf("File description: got = %q, want only the first sentence", got)
	}
}

func TestMarkdownFileReturnsTableError(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	fr := &malcontent.FileReport{Path: "/bin/x", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{{ID: "net/connect", RiskScore: 3}}}
	err := NewMarkdown(&buf).File(&markdownCountdownCtx{Context: t.Context()}, fr)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("File error: got = %v, want = %v", err, context.Canceled)
	}
}

// markdownDiffReport covers every diff section, with entries that must be
// hidden placed ahead of entries that must render.
func markdownDiffReport() *malcontent.Report {
	return &malcontent.Report{Diff: renderDiff(
		[]*malcontent.FileReport{
			// PreviousRelPath would make an empty table print its title, so the empty entries prove they are skipped.
			{Path: "/old/empty", PreviousRelPath: "old/empty"},
			{Path: "/old/tool", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{
				{ID: "net/connect", RiskScore: 3, RiskLevel: report.LevelHIGH, RuleURL: "https://r/connect"},
			}},
		},
		[]*malcontent.FileReport{
			{Path: "/new/empty", PreviousRelPath: "new/empty"},
			{Path: "/new/tool", RiskScore: 2, RiskLevel: report.LevelMEDIUM, Behaviors: []*malcontent.Behavior{
				{ID: "fs/write", RiskScore: 2, RiskLevel: report.LevelMEDIUM, RuleURL: "https://r/write"},
			}},
		},
		[]*malcontent.FileReport{
			{Path: "/mod/empty"},
			{Path: "/mod/same", RiskScore: 1, RiskLevel: report.LevelLOW, Behaviors: []*malcontent.Behavior{
				{ID: "net/listen", RiskScore: 1, RiskLevel: report.LevelLOW, RuleURL: "https://r/listen"},
			}},
			{Path: "/mod/changed", RiskScore: 3, RiskLevel: report.LevelHIGH, PreviousRiskScore: 1, PreviousRiskLevel: report.LevelLOW, Behaviors: []*malcontent.Behavior{
				{ID: "net/bind", RiskScore: 1, RiskLevel: report.LevelLOW, RuleURL: "https://r/bind"},
				{ID: "exec/shell", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true, RuleURL: "https://r/shell"},
				{ID: "fs/read", RiskScore: 1, RiskLevel: report.LevelLOW, DiffRemoved: true, RuleURL: "https://r/read"},
				{ID: "fs/delete", RiskScore: 2, RiskLevel: report.LevelMEDIUM, DiffRemoved: true, RuleURL: "https://r/delete"},
			}},
			{Path: "/mod/new-name", PreviousPath: "/mod/old-name", RiskScore: 2, RiskLevel: report.LevelMEDIUM, PreviousRiskScore: 2, PreviousRiskLevel: report.LevelMEDIUM, Behaviors: []*malcontent.Behavior{
				{ID: "crypto/aes", RiskScore: 2, RiskLevel: report.LevelMEDIUM, DiffAdded: true, RuleURL: "https://r/aes"},
				{ID: "crypto/rc4", RiskScore: 2, RiskLevel: report.LevelMEDIUM, DiffAdded: true, RuleURL: "https://r/rc4"},
			}},
			{Path: "/mod/pruned", RiskScore: 1, RiskLevel: report.LevelLOW, PreviousRiskScore: 1, PreviousRiskLevel: report.LevelLOW, Behaviors: []*malcontent.Behavior{
				{ID: "os/env", RiskScore: 1, RiskLevel: report.LevelLOW, DiffRemoved: true, RuleURL: "https://r/env"},
			}},
		},
	)}
}

func TestMarkdownFullRendersDiffSections(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := NewMarkdown(&buf).Full(t.Context(), &malcontent.Config{}, markdownDiffReport()); err != nil {
		t.Fatalf("Full: got err = %v, want = nil", err)
	}
	got := buf.String()

	want := []string{
		"## Deleted: /old/tool [" + riskEmoji(3) + " HIGH]\n\n",
		"| -HIGH | [net/connect](https://r/connect) |",
		"## Added: /new/tool [" + riskEmoji(2) + " MEDIUM]\n\n",
		"| +MEDIUM | **[fs/write](https://r/write)** |",
		"## Changed (1 added, 2 removed): /mod/changed [" + riskEmoji(1) + " LOW → " + riskEmoji(3) + " HIGH]\n\n",
		"### 1 new behavior\n\n",
		"| +HIGH | **[exec/shell](https://r/shell)** |",
		"### 2 removed behaviors\n\n",
		"| -MEDIUM | [fs/delete](https://r/delete) |",
		"| -LOW | [fs/read](https://r/read) |",
		"## Moved (2 added, 0 removed): /mod/old-name -> /mod/new-name\n\n",
		"### 2 new behaviors\n\n",
		"| +MEDIUM | **[crypto/aes](https://r/aes)** |",
		"| +MEDIUM | **[crypto/rc4](https://r/rc4)** |",
		"## Changed (0 added, 1 removed): /mod/pruned\n\n",
		"### 1 removed behavior\n\n",
		"| -LOW | [os/env](https://r/env) |",
	}
	if !renderIndexOrder(got, want...) {
		t.Errorf("Full output: got = %q, want in order %q", got, want)
	}
	for _, absent := range []string{"/old/empty", "/new/empty", "/mod/empty", "/mod/same", "net/listen", "[net/bind]", "### 0 "} {
		if strings.Contains(got, absent) {
			t.Errorf("Full output: got %q in %q, want = absent", absent, got)
		}
	}
	if n := strings.Count(got, "\n## "); n != 4 {
		t.Errorf("Full file sections after the first: got = %d, want = 4", n)
	}
}

func TestMarkdownFullReturnsTableErrors(t *testing.T) {
	t.Parallel()
	changed := &malcontent.FileReport{Path: "/mod/changed", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{
		{ID: "exec/shell", RiskScore: 3, RiskLevel: report.LevelHIGH, DiffAdded: true},
		{ID: "fs/read", RiskScore: 1, RiskLevel: report.LevelLOW, DiffRemoved: true},
	}}
	tool := func() *malcontent.FileReport {
		return &malcontent.FileReport{Path: "/tool", RiskScore: 3, RiskLevel: report.LevelHIGH, Behaviors: []*malcontent.Behavior{{ID: "net/connect", RiskScore: 3}}}
	}
	// allowed counts the cancellation checks that pass: one in Full, then one per table rendered.
	tests := []struct {
		name    string
		diff    *malcontent.DiffReport
		allowed int
	}{
		{name: "deleted file table", diff: renderDiff([]*malcontent.FileReport{tool()}, nil, nil), allowed: 1},
		{name: "added file table", diff: renderDiff(nil, []*malcontent.FileReport{tool()}, nil), allowed: 1},
		{name: "new behaviors table", diff: renderDiff(nil, nil, []*malcontent.FileReport{changed}), allowed: 1},
		{name: "removed behaviors table", diff: renderDiff(nil, nil, []*malcontent.FileReport{changed}), allowed: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			ctx := &markdownCountdownCtx{Context: t.Context(), allowed: tt.allowed}
			err := NewMarkdown(&buf).Full(ctx, &malcontent.Config{}, &malcontent.Report{Diff: tt.diff})
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Full error: got = %v, want = %v", err, context.Canceled)
			}
		})
	}
}

func TestMarkdownTableSortsByRiskThenKey(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{Path: "/bin/x", Behaviors: []*malcontent.Behavior{
		{ID: "z/b", RiskScore: 3, RiskLevel: report.LevelHIGH},
		{ID: "m/x", RiskScore: 2, RiskLevel: report.LevelMEDIUM},
		{ID: "a/b", RiskScore: 3, RiskLevel: report.LevelHIGH},
		{ID: "q/y", RiskScore: 4, RiskLevel: report.LevelCRITICAL},
		{ID: "c/c", RiskScore: 1, RiskLevel: report.LevelLOW},
	}}
	var buf bytes.Buffer
	if err := markdownTable(t.Context(), fr, &buf, tableConfig{}); err != nil {
		t.Fatalf("markdownTable: got err = %v, want = nil", err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, "| RISK |") {
		t.Errorf("markdownTable without title: got = %q, want table first", got)
	}
	want := []string{"[q/y]", "[a/b]", "[z/b]", "[m/x]", "[c/c]"}
	if !renderIndexOrder(got, want...) {
		t.Errorf("markdownTable order: got = %q, want order %q", got, want)
	}
}

func TestMarkdownTableRowSelection(t *testing.T) {
	t.Parallel()
	// Behaviors sort as listed: unchanged, added, removed, unchanged.
	behaviors := func() []*malcontent.Behavior {
		return []*malcontent.Behavior{
			{ID: "net/unchanged", RiskScore: 4, RiskLevel: report.LevelCRITICAL, RuleURL: "https://r/unchanged"},
			{ID: "net/added", RiskScore: 3, RiskLevel: report.LevelHIGH, RuleURL: "https://r/added", DiffAdded: true},
			{ID: "net/removed", RiskScore: 2, RiskLevel: report.LevelMEDIUM, RuleURL: "https://r/removed", DiffRemoved: true},
			{ID: "net/zlast", RiskScore: 1, RiskLevel: report.LevelLOW, RuleURL: "https://r/zlast"},
		}
	}
	const (
		unchangedRow = "| CRITICAL | [net/unchanged](https://r/unchanged) |"
		addedRow     = "| +HIGH | **[net/added](https://r/added)** |"
		removedRow   = "| -MEDIUM | [net/removed](https://r/removed) |"
		lastRow      = "| LOW | [net/zlast](https://r/zlast) |"
	)
	tests := []struct {
		name    string
		rc      tableConfig
		present []string
		absent  []string
	}{
		{name: "default shows every behavior with diff markers", present: []string{unchangedRow, addedRow, removedRow, lastRow}},
		{name: "skip existing keeps only changed behaviors", rc: tableConfig{SkipExisting: true}, present: []string{addedRow, removedRow}, absent: []string{"net/unchanged", "net/zlast"}},
		{name: "skip no-diff keeps only changed behaviors", rc: tableConfig{SkipNoDiff: true}, present: []string{addedRow, removedRow}, absent: []string{"net/unchanged", "net/zlast"}},
		{name: "no-diff with skip no-diff drops every behavior", rc: tableConfig{NoDiff: true, SkipNoDiff: true}, absent: []string{"net/unchanged", "net/added", "net/removed", "net/zlast"}},
		{name: "skip added drops only added behaviors", rc: tableConfig{SkipAdded: true}, present: []string{unchangedRow, removedRow, lastRow}, absent: []string{"net/added"}},
		{name: "skip removed drops only removed behaviors", rc: tableConfig{SkipRemoved: true}, present: []string{unchangedRow, addedRow, lastRow}, absent: []string{"net/removed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			fr := &malcontent.FileReport{Path: "/bin/x", Behaviors: behaviors()}
			if err := markdownTable(t.Context(), fr, &buf, tt.rc); err != nil {
				t.Fatalf("markdownTable: got err = %v, want = nil", err)
			}
			got := buf.String()
			if !renderIndexOrder(got, tt.present...) {
				t.Errorf("markdownTable rows: got = %q, want in order %q", got, tt.present)
			}
			for _, a := range tt.absent {
				if strings.Contains(got, a) {
					t.Errorf("markdownTable rows: got %q in %q, want = absent", a, got)
				}
			}
		})
	}
}

func TestMarkdownTableFileLevelDiffMarkers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rc   tableConfig
		want string
	}{
		{name: "added file marks every row added", rc: tableConfig{DiffAdded: true}, want: "| +HIGH | **[net/connect](https://r/connect)** |"},
		{name: "removed file marks every row removed", rc: tableConfig{DiffRemoved: true}, want: "| -HIGH | [net/connect](https://r/connect) |"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			fr := &malcontent.FileReport{Path: "/bin/x", Behaviors: []*malcontent.Behavior{
				{ID: "net/connect", RiskScore: 3, RiskLevel: report.LevelHIGH, RuleURL: "https://r/connect"},
			}}
			if err := markdownTable(t.Context(), fr, &buf, tt.rc); err != nil {
				t.Fatalf("markdownTable: got err = %v, want = nil", err)
			}
			if got := buf.String(); !strings.Contains(got, tt.want) {
				t.Errorf("markdownTable row: got = %q, want row %q", got, tt.want)
			}
		})
	}
}

func TestMarkdownTableWithoutRows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		fr   *malcontent.FileReport
		rc   tableConfig
		want string
	}{
		{name: "moved file without behaviors prints its title", fr: &malcontent.FileReport{Path: "/new", PreviousRelPath: "old"}, rc: tableConfig{Title: "## Moved"}, want: "## Moved\n\n"},
		{name: "unmoved file without behaviors prints nothing", fr: &malcontent.FileReport{Path: "/new"}, rc: tableConfig{Title: "## Changed"}},
		{name: "moved file without behaviors or title prints nothing", fr: &malcontent.FileReport{Path: "/new", PreviousRelPath: "old"}},
		{name: "skipped file prints nothing", fr: &malcontent.FileReport{Path: "/new", Skipped: "data", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}}, rc: tableConfig{Title: "## Skipped"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := markdownTable(t.Context(), tt.fr, &buf, tt.rc); err != nil {
				t.Fatalf("markdownTable: got err = %v, want = nil", err)
			}
			if got := buf.String(); got != tt.want {
				t.Errorf("markdownTable output: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestMarkdownTableCanceledContext(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	fr := &malcontent.FileReport{Path: "/bin/x", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}}
	err := markdownTable(renderCanceledContext(t), fr, &buf, tableConfig{Title: "## /bin/x"})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("markdownTable error: got = %v, want = %v", err, context.Canceled)
	}
	if buf.Len() != 0 {
		t.Errorf("markdownTable output: got = %q, want = empty", buf.String())
	}
}

func TestMatchFragmentLinkKeepsURLsOutOfCodeSearch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input      string
		wantSearch bool
	}{
		{input: "https://evil.example/payload"},
		{input: "http://evil.example/payload"},
		{input: "ftp://evil.example/payload", wantSearch: true},
		{input: "httpd.conf", wantSearch: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got := matchFragmentLink(tt.input)
			if isSearch := strings.Contains(got, "github.com/search"); isSearch != tt.wantSearch {
				t.Errorf("matchFragmentLink(%q) = %q: GitHub code search link got = %v, want = %v", tt.input, got, isSearch, tt.wantSearch)
			}
		})
	}
}

func TestMatchFragmentLinkMarkdown(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain URL links to itself",
			input: "https://example.com/path?q=1&r=2",
			want:  `[https:&#8203;//example.com/path?q=1&amp;r=2](<https://example.com/path?q=1\&r=2>)`,
		},
		{
			name:  "URL with parentheses and spaces keeps them in the destination",
			input: "https://example.com/a b)c(d",
			want:  `[https:&#8203;//example.com/a b\)c\(d](<https://example.com/a b)c(d>)`,
		},
		{
			name:  "URL with angle brackets cannot open an HTML tag",
			input: "http://example.com/<script>alert(1)</script>",
			want:  `[http:&#8203;//example.com/\<script\>alert\(1\)\</script\>](<http://example.com/%3Cscript%3Ealert(1)%3C/script%3E>)`,
		},
		{
			name:  "URL that closes the destination early stays inside the link",
			input: "https://a.example/>)[x](javascript:alert(1))",
			want:  `[https:&#8203;//a.example/\>\)\[x\]\(javascript:&#8203;alert\(1\)\)](<https://a.example/%3E)[x](javascript:alert(1))>)`,
		},
		{
			name:  "backslash, pipe, and line ending cannot end the link or the table cell",
			input: "https://a.example/x\\]|y\nz",
			want:  `[https:&#8203;//a.example/x\\\]\|y%0Az](<https://a.example/x%5C]%7Cy%0Az>)`,
		},
		{
			name:  "URL text cannot add emphasis or strikethrough",
			input: "https://example.com/*a*_b_~~c~~",
			want:  `[https:&#8203;//example.com/\*a\*\_b\_\~\~c\~\~](<https://example.com/*a*_b_~~c~~>)`,
		},
		{
			name:  "non-URL fragment links to GitHub code search",
			input: "foo bar(baz)",
			want:  `[foo bar\(baz\)](https://github.com/search?q=foo+bar%28baz%29&type=code)`,
		},
		{
			name:  "non-URL fragment cannot end the link text early",
			input: `foo\](javascript:alert(1))`,
			want:  `[foo\\\]\(javascript:&#8203;alert\(1\)\)](https://github.com/search?q=foo%5C%5D%28javascript%3Aalert%281%29%29&type=code)`,
		},
		{
			name:  "non-URL fragment cannot split the table cell",
			input: "a|b",
			want:  `[a\|b](https://github.com/search?q=a%7Cb&type=code)`,
		},
		{
			name:  "non-URL fragment cannot inject inline HTML",
			input: "<img src=x onerror=alert(1)>",
			want:  `[\<img src=x onerror=alert\(1\)\>](https://github.com/search?q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E&type=code)`,
		},
		{
			name:  "non-URL fragment cannot add emphasis, strikethrough, code, or math",
			input: "*b* _i_ ~~s~~ `c` $m$",
			want:  "[\\*b\\* \\_i\\_ \\~\\~s\\~\\~ \\`c\\` \\$m\\$](https://github.com/search?q=%2Ab%2A+_i_+~~s~~+%60c%60+%24m%24&type=code)",
		},
		{
			name:  "URL text cannot mention users, reference issues, or add emoji",
			input: "https://user@example.com/:smile:#12",
			want:  `[https:&#8203;//user@&#8203;example.com/:&#8203;smile:&#8203;#&#8203;12](<https://user@example.com/:smile:#12>)`,
		},
		{
			name:  "URL keeps an entity spelled out in it literal in text and destination",
			input: "https://x.example/?a=1&amp;b=&#64;",
			want:  `[https:&#8203;//x.example/?a=1&amp;amp;b=&amp;#&#8203;64;](<https://x.example/?a=1\&amp;b=\&#64;>)`,
		},
		{
			name:  "non-URL fragment cannot mention a user",
			input: "@user",
			want:  `[@&#8203;user](https://github.com/search?q=%40user&type=code)`,
		},
		{
			name:  "non-URL fragment cannot reference an issue in another repository",
			input: "org/repo#12",
			want:  `[org/repo#&#8203;12](https://github.com/search?q=org%2Frepo%2312&type=code)`,
		},
		{
			name:  "non-URL fragment cannot reference an issue",
			input: "#12",
			want:  `[#&#8203;12](https://github.com/search?q=%2312&type=code)`,
		},
		{
			name:  "non-URL fragment cannot add an emoji shortcode",
			input: ":smile:",
			want:  `[:&#8203;smile:&#8203;](https://github.com/search?q=%3Asmile%3A&type=code)`,
		},
		{
			name:  "non-URL fragment keeps a spelled-out entity literal",
			input: "&#64;",
			want:  `[&amp;#&#8203;64;](https://github.com/search?q=%26%2364%3B&type=code)`,
		},
		{
			name:  "code span keeps mention, reference, and emoji characters literal",
			input: "$@user#12:smile:&amp;",
			want:  "`$@user#12:smile:&amp;`",
		},
		{
			name:  "non-URL fragment line ending cannot end the table row",
			input: "line1\r\nline2",
			want:  `[line1%0D%0Aline2](https://github.com/search?q=line1%0D%0Aline2&type=code)`,
		},
		{
			name:  "YARA string name renders as code",
			input: "$xor_key",
			want:  "`$xor_key`",
		},
		{
			name:  "code span fence is longer than a backtick inside it",
			input: "$a`b",
			want:  "``$a`b``",
		},
		{
			name:  "code span fence is longer than the longest backtick run",
			input: "$a``b```c",
			want:  "````$a``b```c````",
		},
		{
			name:  "code span ending in a backtick is padded",
			input: "$x`",
			want:  "`` $x` ``",
		},
		{
			name:  "code span ending in a space is padded",
			input: "$x ",
			want:  "` $x  `",
		},
		{
			name:  "code span cannot split the table cell or end the row",
			input: "$a|b\nc",
			want:  "`$a\\|b%0Ac`",
		},
		{
			name:  "code span keeps Markdown characters literal",
			input: "$<b>*x*</b>[y](z)",
			want:  "`$<b>*x*</b>[y](z)`",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchFragmentLink(tt.input); got != tt.want {
				t.Errorf("matchFragmentLink(%q):\ngot  = %s\nwant = %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestMarkdownTableKeepsURLEvidenceInOneCell(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{Path: "/bin/x", Behaviors: []*malcontent.Behavior{{
		ID:           "net/url",
		Description:  "fetches URLs",
		MatchStrings: []string{"https://a.example/x|y z>"},
		RiskScore:    1,
		RiskLevel:    report.LevelLOW,
		RuleURL:      "https://r/url",
	}}}
	var buf bytes.Buffer
	if err := markdownTable(t.Context(), fr, &buf, tableConfig{}); err != nil {
		t.Fatalf("markdownTable: got err = %v, want = nil", err)
	}
	var row string
	for line := range strings.Lines(buf.String()) {
		if strings.HasPrefix(line, "| LOW ") {
			row = strings.TrimSuffix(line, "\n")
		}
	}
	const link = `[https:&#8203;//a.example/x\|y z\>](<https://a.example/x%7Cy z%3E>)`
	if !strings.HasSuffix(row, "| "+link+" |") {
		t.Errorf("evidence cell: got row = %q, want it to end with %q", row, "| "+link+" |")
	}
	// Four cells need five unescaped column separators.
	if got := strings.Count(row, "|") - strings.Count(row, `\|`); got != 5 {
		t.Errorf("column separators: got = %d, want = 5 in %q", got, row)
	}
}

func TestMarkdownTablePreservesCellContent(t *testing.T) {
	t.Parallel()
	fr := &malcontent.FileReport{Path: "/bin/x", Behaviors: []*malcontent.Behavior{
		{
			ID:           "net/url",
			Description:  "keeps  two  spaces --- and dashes",
			MatchStrings: []string{"https://example.com/a---b  c"},
			RiskScore:    1,
			RiskLevel:    report.LevelLOW,
			RuleURL:      "https://r/url",
		},
		{ID: "net/zz", Description: "no evidence", RiskScore: 1, RiskLevel: report.LevelLOW, RuleURL: "https://r/zz"},
	}}
	want := "| RISK | KEY | DESCRIPTION | EVIDENCE |\n" +
		"|:--|:--|:--|:--|\n" +
		"| LOW | [net/url](https://r/url) | keeps  two  spaces --- and dashes | [https:&#8203;//example.com/a---b  c](<https://example.com/a---b  c>) |\n" +
		"| LOW | [net/zz](https://r/zz) | no evidence | |\n" +
		"\n"

	var buf bytes.Buffer
	if err := markdownTable(t.Context(), fr, &buf, tableConfig{}); err != nil {
		t.Fatalf("markdownTable: got err = %v, want = nil", err)
	}
	if got := buf.String(); got != want {
		t.Errorf("markdownTable output:\ngot  = %q\nwant = %q", got, want)
	}
}

const (
	markdownEvilPath      = "evil[x](javascript:alert(1))<img src=x>@user#1*b*`c`\nnext"
	markdownEvilPathShown = "evil\\[x\\]\\(javascript:&#8203;alert\\(1\\)\\)\\<img src=x\\>@&#8203;user#&#8203;1\\*b\\*\\`c\\`%0Anext"
)

// markdownEvilReport returns a report at path with one behavior, optionally marked as added.
func markdownEvilReport(path string, added bool) *malcontent.FileReport {
	return &malcontent.FileReport{
		Path:              path,
		RiskScore:         3,
		RiskLevel:         report.LevelHIGH,
		PreviousRiskScore: 3,
		PreviousRiskLevel: report.LevelHIGH,
		Behaviors: []*malcontent.Behavior{
			{ID: "net/connect", RiskScore: 3, RiskLevel: report.LevelHIGH, RuleURL: "https://r/connect", DiffAdded: added},
		},
	}
}

func TestMarkdownEscapesPathsInHeadings(t *testing.T) {
	t.Parallel()
	changed := markdownEvilReport(markdownEvilPath, true)
	changed.PreviousRiskScore = 2
	changed.PreviousRiskLevel = report.LevelMEDIUM
	moved := markdownEvilReport(markdownEvilPath+"-moved", true)
	moved.PreviousPath = markdownEvilPath + "-old"
	diff := &malcontent.Report{Diff: renderDiff(
		[]*malcontent.FileReport{markdownEvilReport(markdownEvilPath, false)},
		[]*malcontent.FileReport{markdownEvilReport(markdownEvilPath+"-a", false)},
		[]*malcontent.FileReport{changed, moved},
	)}

	tests := []struct {
		name   string
		render func(t *testing.T, w io.Writer) error
		want   []string
	}{
		{
			name: "scan heading",
			render: func(t *testing.T, w io.Writer) error {
				t.Helper()
				return NewMarkdown(w).File(t.Context(), markdownEvilReport(markdownEvilPath, false))
			},
			want: []string{"## " + markdownEvilPathShown + " [" + riskEmoji(3) + " HIGH]\n\n"},
		},
		{
			name: "diff headings",
			render: func(t *testing.T, w io.Writer) error {
				t.Helper()
				return NewMarkdown(w).Full(t.Context(), &malcontent.Config{}, diff)
			},
			want: []string{
				"## Deleted: " + markdownEvilPathShown + " [" + riskEmoji(3) + " HIGH]\n\n",
				"## Added: " + markdownEvilPathShown + "-a [" + riskEmoji(3) + " HIGH]\n\n",
				"## Changed (1 added, 0 removed): " + markdownEvilPathShown + " [" + riskEmoji(2) + " MEDIUM → " + riskEmoji(3) + " HIGH]\n\n",
				"## Moved (1 added, 0 removed): " + markdownEvilPathShown + "-old -> " + markdownEvilPathShown + "-moved\n\n",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := tt.render(t, &buf); err != nil {
				t.Fatalf("render: got err = %v, want = nil", err)
			}
			got := buf.String()
			if !renderIndexOrder(got, tt.want...) {
				t.Errorf("headings: got = %q, want in order %q", got, tt.want)
			}
			// The newline in the path must not start a new Markdown line.
			for line := range strings.Lines(got) {
				if strings.HasPrefix(line, "next") {
					t.Errorf("line from the path: got = %q, want = none", line)
				}
			}
		})
	}
}

func TestMarkdownCodeSpanPadding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "leading backtick is padded", in: "`a", want: "`` `a ``"},
		{name: "trailing backtick is padded", in: "a`", want: "`` a` ``"},
		{name: "leading space is padded", in: " a", want: "`  a `"},
		{name: "trailing space is padded", in: "a ", want: "` a  `"},
		{name: "plain content is not padded", in: "a", want: "`a`"},
		{name: "inner backtick run sets the fence", in: "a``b", want: "```a``b```"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := markdownCodeSpan(tt.in); got != tt.want {
				t.Errorf("markdownCodeSpan(%q): got = %q, want = %q", tt.in, got, tt.want)
			}
		})
	}
}
