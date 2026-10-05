// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
)

func TestPkgStatisticsOrdersByShareDescending(t *testing.T) {
	t.Parallel()
	const longKey = "exec/program/launch"
	files := xsync.NewMap[string, *malcontent.FileReport]()
	files.Store("/a", &malcontent.FileReport{Path: "/a", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}, {ID: "fs/read"}, {ID: longKey}}})
	files.Store("/b", &malcontent.FileReport{Path: "/b", Behaviors: []*malcontent.Behavior{{ID: "fs/read"}, {ID: "net/connect"}}})
	files.Store("/c", &malcontent.FileReport{Path: "/c", Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}})

	stats, width, total := PkgStatistics(&malcontent.Config{}, files)
	if total != 6 {
		t.Errorf("total behaviors: got = %d, want = 6", total)
	}
	if width != len(longKey) {
		t.Errorf("width: got = %d, want = %d", width, len(longKey))
	}
	want := []struct {
		key   string
		count int
	}{{"net/connect", 3}, {"fs/read", 2}, {longKey, 1}}
	if len(stats) != len(want) {
		t.Fatalf("stats: got = %+v, want %d entries", stats, len(want))
	}
	for i, w := range want {
		got := stats[i]
		if got.Key != w.key || got.Count != w.count || got.Total != 6 {
			t.Errorf("stats[%d]: got = %+v, want key=%s count=%d total=6", i, got, w.key, w.count)
		}
		if share := float64(w.count) / 6 * 100; math.Abs(got.Value-share) > 1e-9 {
			t.Errorf("stats[%d].Value: got = %v, want = %v", i, got.Value, share)
		}
	}
}

func TestPkgStatisticsShortKeysKeepMinimumWidth(t *testing.T) {
	t.Parallel()
	files := xsync.NewMap[string, *malcontent.FileReport]()
	files.Store("/a", &malcontent.FileReport{Path: "/a", Behaviors: []*malcontent.Behavior{{ID: "a/b"}}})
	if _, width, _ := PkgStatistics(&malcontent.Config{}, files); width != 10 {
		t.Errorf("width: got = %d, want = 10", width)
	}
}

func TestSerializedStatsSortsByKey(t *testing.T) {
	t.Parallel()
	files := xsync.NewMap[string, *malcontent.FileReport]()
	files.Store("/a", &malcontent.FileReport{Path: "/a", RiskScore: 3, Behaviors: []*malcontent.Behavior{{ID: "net/connect"}, {ID: "exec/shell"}}})
	files.Store("/b", &malcontent.FileReport{Path: "/b", RiskScore: 1, Behaviors: []*malcontent.Behavior{{ID: "net/connect"}, {ID: "anti-static/xor"}}})
	files.Store("/c", &malcontent.FileReport{Path: "/c", RiskScore: 2, Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}})

	got := serializedStats(&malcontent.Config{}, &malcontent.Report{Files: files})
	if got == nil {
		t.Fatal("serializedStats: got = nil, want = stats")
	}

	pkgKeys := make([]string, 0, len(got.PkgStats))
	for _, s := range got.PkgStats {
		pkgKeys = append(pkgKeys, s.Key)
	}
	if want := []string{"anti-static/xor", "exec/shell", "net/connect"}; !slices.Equal(pkgKeys, want) {
		t.Errorf("PkgStats keys: got = %v, want = %v", pkgKeys, want)
	}

	riskKeys := make([]int, 0, len(got.RiskStats))
	for _, s := range got.RiskStats {
		riskKeys = append(riskKeys, s.Key)
	}
	if want := []int{1, 2, 3}; !slices.Equal(riskKeys, want) {
		t.Errorf("RiskStats keys: got = %v, want = %v", riskKeys, want)
	}

	if got.ProcessedFiles != 3 || got.SkippedFiles != 0 || got.TotalBehaviors != 5 || got.TotalRisks != 3 {
		t.Errorf("totals: got = %+v, want processed=3 skipped=0 behaviors=5 risks=3", got)
	}
}

func TestStatisticsNilReport(t *testing.T) {
	t.Parallel()
	if err := Statistics(&malcontent.Config{}, nil); err == nil {
		t.Error("Statistics(nil): got err = nil, want = error")
	}
}

func TestRiskStatisticsSharesInDescendingOrder(t *testing.T) {
	t.Parallel()
	files := xsync.NewMap[string, *malcontent.FileReport]()
	for i, score := range []int{3, 3, 3, 2, 2, 1} {
		path := "/f" + strings.Repeat("x", i)
		files.Store(path, &malcontent.FileReport{Path: path, RiskScore: score})
	}

	stats, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{}, files)
	if processed != 6 || skipped != 0 || totalRisks != 6 {
		t.Errorf("totals: got processed=%d skipped=%d risks=%d, want processed=6 skipped=0 risks=6", processed, skipped, totalRisks)
	}
	want := []struct{ key, count int }{{3, 3}, {2, 2}, {1, 1}}
	if len(stats) != len(want) {
		t.Fatalf("stats: got = %+v, want %d entries", stats, len(want))
	}
	for i, w := range want {
		got := stats[i]
		if got.Key != w.key || got.Count != w.count || got.Total != 6 {
			t.Errorf("stats[%d]: got = %+v, want key=%d count=%d total=6", i, got, w.key, w.count)
		}
		if share := float64(w.count) / 6 * 100; math.Abs(got.Value-share) > 1e-9 {
			t.Errorf("stats[%d].Value: got = %v, want = %v", i, got.Value, share)
		}
	}
}

func TestStatisticsIgnoreEmptyKeysAndNilReports(t *testing.T) {
	t.Parallel()
	files := xsync.NewMap[string, *malcontent.FileReport]()
	files.Store("/bin/tool", &malcontent.FileReport{Path: "/bin/tool", RiskScore: 3, Behaviors: []*malcontent.Behavior{{ID: "net/connect"}}})
	files.Store("", &malcontent.FileReport{Path: "unnamed", RiskScore: 3, Behaviors: []*malcontent.Behavior{{ID: "fs/read"}}})
	files.Store("/bin/missing", nil)

	riskStats, totalRisks, processed, skipped := RiskStatistics(&malcontent.Config{}, files)
	if processed != 1 || skipped != 0 || totalRisks != 1 {
		t.Errorf("RiskStatistics totals: got processed=%d skipped=%d risks=%d, want processed=1 skipped=0 risks=1", processed, skipped, totalRisks)
	}
	if len(riskStats) != 1 || riskStats[0].Count != 1 {
		t.Errorf("RiskStatistics stats: got = %+v, want one entry with count 1", riskStats)
	}

	pkgStats, _, totalBehaviors := PkgStatistics(&malcontent.Config{}, files)
	if totalBehaviors != 1 {
		t.Errorf("PkgStatistics behaviors: got = %d, want = 1", totalBehaviors)
	}
	if len(pkgStats) != 1 || pkgStats[0].Key != "net/connect" {
		t.Errorf("PkgStatistics stats: got = %+v, want only net/connect", pkgStats)
	}
}

// Statistics prints to os.Stdout, so this test swaps it and must not run in parallel.
func TestStatisticsWritesSummary(t *testing.T) {
	files := xsync.NewMap[string, *malcontent.FileReport]()
	add := func(name string, score, n int, id string) {
		for i := range n {
			path := fmt.Sprintf("/%s-%d", name, i)
			files.Store(path, &malcontent.FileReport{Path: path, RiskScore: score, Behaviors: []*malcontent.Behavior{{ID: id}}})
		}
	}
	add("low", 1, 4, "a/one")
	add("med", 2, 3, "b/two")
	add("high", 3, 2, "c/three")
	add("crit", 4, 1, "d/four")
	files.Store("/skipped", &malcontent.FileReport{Path: "/skipped", Skipped: "data file"})

	want := "\U0001F4CA Statistics\n" +
		"---\n" +
		"\x1b[1;37mFiles Scanned   \x1b[1;37m11 (1 skipped)\x1b[0m\n" +
		"\x1b[1;37mTotal Risks     \x1b[1;37m10\x1b[0m\n" +
		"---\n" +
		"\u26a0\ufe0f  Risk Level Percentage\n" +
		"---\n" +
		"\x1b[1;37mRisk Level    \x1b[1;37mPercentage Count/Total\x1b[0m\n" +
		"\x1b[32m1/LOW" + strings.Repeat(" ", 13) + "36.36% 4/11\x1b[0m\n" +
		"\x1b[33m2/MED" + strings.Repeat(" ", 13) + "27.27% 3/11\x1b[0m\n" +
		"\x1b[31m3/HIGH" + strings.Repeat(" ", 12) + "18.18% 2/11\x1b[0m\n" +
		"\x1b[35m4/CRIT" + strings.Repeat(" ", 13) + "9.09% 1/11\x1b[0m\n" +
		"---\n" +
		"\x1b[1;37mNumber of behaviors \x1b[1;37m        10\x1b[0m\n" +
		"---\n" +
		"\U0001F4E6 Package Behaviors\n" +
		"---\n" +
		"\x1b[1;37mNamespace   \x1b[1;37mPercentage Count/Total\x1b[0m\n" +
		"a/one" + strings.Repeat(" ", 11) + "40.00% 4/10\n" +
		"b/two" + strings.Repeat(" ", 11) + "30.00% 3/10\n" +
		"c/three" + strings.Repeat(" ", 9) + "20.00% 2/10\n" +
		"d/four" + strings.Repeat(" ", 10) + "10.00% 1/10\n"

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: got err = %v, want = nil", err)
	}
	stdout := os.Stdout
	t.Cleanup(func() { os.Stdout = stdout })
	os.Stdout = w
	statsErr := Statistics(&malcontent.Config{}, &malcontent.Report{Files: files})
	os.Stdout = stdout
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: got err = %v, want = nil", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: got err = %v, want = nil", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close pipe reader: got err = %v, want = nil", err)
	}

	if statsErr != nil {
		t.Fatalf("Statistics: got err = %v, want = nil", statsErr)
	}
	if got := string(out); got != want {
		t.Errorf("Statistics output:\ngot  = %q\nwant = %q", got, want)
	}
}
