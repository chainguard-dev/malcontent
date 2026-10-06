// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"cmp"
	"fmt"
	"os"
	"slices"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/puzpuzpuz/xsync/v4"
)

func RiskStatistics(c *malcontent.Config, files *xsync.Map[string, *malcontent.FileReport]) ([]malcontent.IntMetric, int, int, int) {
	// Files counted at each risk score.
	riskCounts := map[int]int{}

	processedFiles := 0
	skippedFiles := 0
	files.Range(func(key string, fr *malcontent.FileReport) bool {
		if key == "" || fr == nil {
			return true
		}
		processedFiles++

		switch {
		case c.Scan:
			if fr.RiskScore >= 3 {
				riskCounts[fr.RiskScore]++
			} else {
				skippedFiles++
			}
		default:
			if fr.Skipped == "" {
				riskCounts[fr.RiskScore]++
			} else {
				skippedFiles++
			}
		}
		return true
	})

	stats := make([]malcontent.IntMetric, 0, len(riskCounts))
	total := 0
	for k, n := range riskCounts {
		total += n
		stats = append(stats, malcontent.IntMetric{Key: k, Value: (float64(n) / float64(processedFiles)) * 100, Count: n, Total: processedFiles})
	}
	// Descending by share.
	slices.SortFunc(stats, func(a, b malcontent.IntMetric) int {
		return cmp.Compare(b.Value, a.Value)
	})

	return stats, total, processedFiles, skippedFiles
}

func PkgStatistics(_ *malcontent.Config, files *xsync.Map[string, *malcontent.FileReport]) ([]malcontent.StrMetric, int, int) {
	length := files.Size()
	numBehaviors := 0
	pkgMap := make(map[string]int, length)
	pkg := make(map[string]float64, length)
	files.Range(func(key string, fr *malcontent.FileReport) bool {
		if key == "" || fr == nil {
			return true
		}
		if fr.Skipped == "" {
			for _, b := range fr.Behaviors {
				numBehaviors++
				pkgMap[b.ID]++
			}
		}
		return true
	})

	for namespace, count := range pkgMap {
		pkg[namespace] = (float64(count) / float64(numBehaviors)) * 100
	}

	width := 10
	for k := range pkg {
		width = max(width, len(k))
	}
	stats := make([]malcontent.StrMetric, 0, len(pkg))
	for k, v := range pkg {
		stats = append(stats, malcontent.StrMetric{Key: k, Value: v, Count: pkgMap[k], Total: numBehaviors})
	}
	// Descending by share.
	slices.SortFunc(stats, func(a, b malcontent.StrMetric) int {
		return cmp.Compare(b.Value, a.Value)
	})
	return stats, width, numBehaviors
}

func Statistics(c *malcontent.Config, r *malcontent.Report) error {
	// guard against nil reports
	if r == nil {
		return fmt.Errorf("unexpected nil report")
	}

	riskStats, totalRisks, processedFiles, skippedFiles := RiskStatistics(c, r.Files)
	pkgStats, width, totalBehaviors := PkgStatistics(c, r.Files)

	// Build the summary first and print it with one write.
	var b bytes.Buffer
	statsSymbol := "📊"
	riskSymbol := "⚠️ "
	pkgSymbol := "📦"
	fmt.Fprintf(&b, "%s Statistics\n", statsSymbol)
	fmt.Fprintln(&b, "---")
	fmt.Fprintf(&b, "\033[1;37m%-15s \033[1;37m%s\033[0m\n", "Files Scanned", fmt.Sprintf("%d (%d skipped)", processedFiles, skippedFiles))
	fmt.Fprintf(&b, "\033[1;37m%-15s \033[1;37m%s\033[0m\n", "Total Risks", fmt.Sprintf("%d", totalRisks))
	fmt.Fprintln(&b, "---")
	fmt.Fprintf(&b, "%s Risk Level Percentage\n", riskSymbol)
	fmt.Fprintln(&b, "---")
	fmt.Fprintf(&b, "\033[1;37m%-12s  \033[1;37m%10s %s\033[0m\n", "Risk Level", "Percentage", "Count/Total")
	for _, stat := range riskStats {
		level := ShortRisk(report.RiskLevels[stat.Key])
		color := ""
		switch level {
		case report.LevelNONE:
			color = "\033[0m"
		case report.LevelLOW:
			color = "\033[32m"
		case "MED":
			color = "\033[33m"
		case report.LevelHIGH:
			color = "\033[31m"
		case levelCRIT:
			color = "\033[35m"
		}
		fmt.Fprintf(&b, "%s%-12s %10.2f%s %d/%d\033[0m\n", color, fmt.Sprintf("%d/%s", stat.Key, ShortRisk(level)), stat.Value, "%", stat.Count, stat.Total)
	}

	fmt.Fprintln(&b, "---")
	fmt.Fprintf(&b, "\033[1;37m%-12s \033[1;37m%10s\033[0m\n", "Number of behaviors", fmt.Sprintf("%d", totalBehaviors))
	fmt.Fprintln(&b, "---")
	fmt.Fprintf(&b, "%s Package Behaviors\n", pkgSymbol)
	fmt.Fprintln(&b, "---")
	fmt.Fprintf(&b, "\033[1;37m%-*s  \033[1;37m%10s %s\033[0m\n", width, "Namespace", "Percentage", "Count/Total")
	for _, pkg := range pkgStats {
		fmt.Fprintf(&b, "%-*s %10.2f%s %d/%d\n", width, pkg.Key, pkg.Value, "%", pkg.Count, pkg.Total)
	}

	_, err := os.Stdout.Write(b.Bytes())
	return err
}
