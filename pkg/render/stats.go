package render

import (
	"fmt"
	"sort"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/report"
)

func riskStatistics(files map[string]bincapz.FileReport, riskMap map[int][]string, riskStats map[int]float64) []bincapz.IntMetric {
	for path, rf := range files {
		riskMap[rf.RiskScore] = append(riskMap[rf.RiskScore], path)
		for riskLevel := range riskMap {
			riskStats[riskLevel] = (float64(len(riskMap[riskLevel])) / float64(len(files))) * 100
		}
	}

	var stats []bincapz.IntMetric
	for k, v := range riskStats {
		stats = append(stats, bincapz.IntMetric{Key: k, Value: v})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Value > stats[j].Value
	})

	return stats
}

func pkgStatistics(files map[string]bincapz.FileReport, pkgMap map[string]int) ([]bincapz.StrMetric, int) {
	var numNamespaces int
	pkg := make(map[string]float64)
	for _, rf := range files {
		for _, namespace := range rf.PackageRisk {
			numNamespaces++
			pkgMap[namespace]++
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
		stats = append(stats, bincapz.StrMetric{Key: k, Value: v})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Value > stats[j].Value
	})
	return stats, width
}

func Statistics(r *bincapz.Report) error {
	riskMap := make(map[int][]string)
	pkgMap := make(map[string]int)
	statsMap := make(map[int]float64)
	riskStats := riskStatistics(r.Files, riskMap, statsMap)
	pkgStats, width := pkgStatistics(r.Files, pkgMap)

	statsSymbol := "📊"
	riskSymbol := "⚠️ "
	pkgSymbol := "📦"
	fmt.Printf("%s Statistics\n", statsSymbol)
	fmt.Println("---")
	fmt.Printf("%s Risk Level Percentage\n", riskSymbol)
	fmt.Println("---")
	fmt.Printf("\033[1;37m%-12s \033[1;37m%10s\033[0m\n", "Risk Level", "Percentage")
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
		fmt.Printf("%s%-12s %10.2f%s\033[0m\n", color, fmt.Sprintf("%d/%s", stat.Key, ShortRisk(level)), stat.Value, "%")
	}

	fmt.Println("---")
	fmt.Printf("%s Package Risk Percentage\n", pkgSymbol)
	fmt.Println("---")
	fmt.Printf("\033[1;37m%-*s \033[1;37m%10s\033[0m\n", width, "Package", "Percentage")
	for _, pkg := range pkgStats {
		fmt.Printf("%-*s %10.2f%s\n", width, pkg.Key, pkg.Value, "%")
	}

	return nil
}
