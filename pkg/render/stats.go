package render

import (
	"fmt"
	"sort"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/report"
)

func riskLevelStatistics(files map[string]bincapz.FileReport, riskMap map[int][]string, riskPercentages map[int]float64) []bincapz.Kv {
	for path, rf := range files {
		riskMap[rf.RiskScore] = append(riskMap[rf.RiskScore], path)
		for riskLevel := range riskMap {
			riskPercentages[riskLevel] = (float64(len(riskMap[riskLevel])) / float64(len(files))) * 100
		}
	}

	var riskLevelStatistics []bincapz.Kv
	for k, v := range riskPercentages {
		riskLevelStatistics = append(riskLevelStatistics, bincapz.Kv{Key: k, Value: v})
	}
	sort.Slice(riskLevelStatistics, func(i, j int) bool {
		return riskLevelStatistics[i].Value > riskLevelStatistics[j].Value
	})

	return riskLevelStatistics
}

func packageRiskStatistics(files map[string]bincapz.FileReport, packageRiskMap map[string]int) ([]bincapz.KvStr, int) {
	var numNamespaces int
	packageRiskPercentages := make(map[string]float64)
	for _, rf := range files {
		for _, namespace := range rf.PackageRisk {
			numNamespaces++
			packageRiskMap[namespace]++
		}
	}
	for namespace, count := range packageRiskMap {
		packageRiskPercentages[namespace] = (float64(count) / float64(numNamespaces)) * 100
	}

	width := 10
	for k := range packageRiskPercentages {
		width = func(l int, w int) int {
			if l > w {
				return l
			}
			return w
		}(len(k), width)
	}
	var packageRiskStatistics []bincapz.KvStr
	for k, v := range packageRiskPercentages {
		packageRiskStatistics = append(packageRiskStatistics, bincapz.KvStr{Key: k, Value: v})
	}
	sort.Slice(packageRiskStatistics, func(i, j int) bool {
		return packageRiskStatistics[i].Value > packageRiskStatistics[j].Value
	})
	return packageRiskStatistics, width
}

func Statistics(r *bincapz.Report) error {
	riskMap := make(map[int][]string)
	packageRiskMap := make(map[string]int)
	percentageMap := make(map[int]float64)
	packageRiskPercentages, width := packageRiskStatistics(r.Files, packageRiskMap)
	riskPercentages := riskLevelStatistics(r.Files, riskMap, percentageMap)

	statsSymbol := "📊"
	riskSymbol := "⚠️ "
	packageSymbol := "📦"
	fmt.Printf("%s Statistics\n", statsSymbol)
	fmt.Println("---")
	fmt.Printf("%s Risk Level Percentage\n", riskSymbol)
	fmt.Println("---")
	fmt.Printf("\033[1;37m%-12s \033[1;37m%10s\033[0m\n", "Risk Level", "Percentage")
	for _, stat := range riskPercentages {
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
	fmt.Printf("%s Package Risk Percentage\n", packageSymbol)
	fmt.Println("---")
	fmt.Printf("\033[1;37m%-*s \033[1;37m%10s\033[0m\n", width, "Package", "Percentage")
	for _, pkg := range packageRiskPercentages {
		fmt.Printf("%-*s %10.2f%s\n", width, pkg.Key, pkg.Value, "%")
	}

	return nil
}
