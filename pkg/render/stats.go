package render

import (
	"fmt"
	"sort"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/report"
)

func riskStatistics(files map[string]*bincapz.FileReport) ([]bincapz.IntMetric, int, int) {
	riskMap := make(map[int][]string)
	riskStats := make(map[int]float64)

	// as opposed to skipped files
	processedFiles := 0
	for _, rf := range files {
		if rf.Skipped != "" {
			continue
		}
		processedFiles++
	}

	for path, rf := range files {
		if rf.Skipped != "" {
			continue
		}
		riskMap[rf.RiskScore] = append(riskMap[rf.RiskScore], path)
		for riskLevel := range riskMap {
			riskStats[riskLevel] = (float64(len(riskMap[riskLevel])) / float64(processedFiles)) * 100
		}
	}

	var stats []bincapz.IntMetric
	total := func() int {
		var t int
		for _, v := range riskMap {
			t += len(v)
		}
		return t
	}
	for k, v := range riskStats {
		stats = append(stats, bincapz.IntMetric{Key: k, Value: v, Count: len(riskMap[k]), Total: total()})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Value > stats[j].Value
	})

	return stats, total(), processedFiles
}

func pkgStatistics(files map[string]*bincapz.FileReport) ([]bincapz.StrMetric, int, int) {
	numNamespaces := 0
	pkgMap := make(map[string]int)
	pkg := make(map[string]float64)
	for _, rf := range files {
		for _, namespace := range rf.Behaviors {
			numNamespaces++
			pkgMap[namespace.ID]++
		}
	}
	for namespace, count := range pkgMap {
		pkg[namespace] = (float64(count) / float64(numNamespaces)) * 100
	}

	width := 10
	for k := range pkg {
		width = func(l int, w int) int {
			if l > w {
				return l
			}
			return w
		}(len(k), width)
	}
	var stats []bincapz.StrMetric
	for k, v := range pkg {
		stats = append(stats, bincapz.StrMetric{Key: k, Value: v, Count: pkgMap[k], Total: numNamespaces})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Value > stats[j].Value
	})
	return stats, width, numNamespaces
}

func Statistics(r *bincapz.Report) error {
	riskStats, totalRisks, totalFilesProcessed := riskStatistics(r.Files)
	pkgStats, width, totalPkgs := pkgStatistics(r.Files)

	statsSymbol := "📊"
	riskSymbol := "⚠️ "
	pkgSymbol := "📦"
	fmt.Printf("%s Statistics\n", statsSymbol)
	fmt.Println("---")
	fmt.Printf("\033[1;37m%-15s \033[1;37m%s\033[0m\n", "Files Scanned", fmt.Sprintf("%d (%d skipped)", totalFilesProcessed, len(r.Files)-totalFilesProcessed))
	fmt.Printf("\033[1;37m%-15s \033[1;37m%s\033[0m\n", "Total Risks", fmt.Sprintf("%d", totalRisks))
	fmt.Println("---")
	fmt.Printf("%s Risk Level Percentage\n", riskSymbol)
	fmt.Println("---")
	fmt.Printf("\033[1;37m%-12s  \033[1;37m%10s %s\033[0m\n", "Risk Level", "Percentage", "Count/Total")
	for _, stat := range riskStats {
		level := ShortRisk(report.RiskLevels[stat.Key])
		color := ""
		switch level {
		case "NONE":
			color = "\033[0m"
		case "LOW":
			color = "\033[32m"
		case "MED":
			color = "\033[33m"
		case "HIGH":
			color = "\033[31m"
		case "CRIT":
			color = "\033[35m"
		}
		fmt.Printf("%s%-12s %10.2f%s %d/%d\033[0m\n", color, fmt.Sprintf("%d/%s", stat.Key, ShortRisk(level)), stat.Value, "%", stat.Count, stat.Total)
	}

	fmt.Println("---")
	fmt.Printf("\033[1;37m%-12s \033[1;37m%10s\033[0m\n", "Total Packages", fmt.Sprintf("%d", totalPkgs))
	fmt.Println("---")
	fmt.Printf("%s Package Risk Percentage\n", pkgSymbol)
	fmt.Println("---")
	fmt.Printf("\033[1;37m%-*s  \033[1;37m%10s %s\033[0m\n", width, "Package", "Percentage", "Count/Total")
	for _, pkg := range pkgStats {
		fmt.Printf("%-*s %10.2f%s %d/%d\n", width, pkg.Key, pkg.Value, "%", pkg.Count, pkg.Total)
	}

	return nil
}
