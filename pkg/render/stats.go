package render

import (
	"fmt"
	"sort"
	"sync"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

// smLength returns the length of a sync.Map.
func smLength(m *sync.Map) int {
	length := 0
	m.Range(func(_, _ any) bool {
		length++
		return true
	})
	return length
}

func RiskStatistics(c *malcontent.Config, files *sync.Map) ([]malcontent.IntMetric, int, int, int) {
	length := smLength(files)

	riskMap := make(map[int][]string, length)
	riskStats := make(map[int]float64, length)

	processedFiles := 0
	skippedFiles := 0
	files.Range(func(key, value any) bool {
		if key == nil || value == nil {
			return true
		}
		processedFiles++

		if fr, ok := value.(*malcontent.FileReport); ok {
			switch {
			case c.Scan:
				if fr.RiskScore >= 3 {
					riskMap[fr.RiskScore] = append(riskMap[fr.RiskScore], fr.Path)
				} else {
					skippedFiles++
				}
			default:
				if fr.Skipped == "" {
					riskMap[fr.RiskScore] = append(riskMap[fr.RiskScore], fr.Path)
				} else {
					skippedFiles++
				}
			}
		}
		for riskLevel := range riskMap {
			riskStats[riskLevel] = (float64(len(riskMap[riskLevel])) / float64(processedFiles)) * 100
		}
		return true
	})

	stats := make([]malcontent.IntMetric, 0, len(riskStats))
	total := func() int {
		var t int
		for _, v := range riskMap {
			t += len(v)
		}
		return t
	}
	for k, v := range riskStats {
		stats = append(stats, malcontent.IntMetric{Key: k, Value: v, Count: len(riskMap[k]), Total: processedFiles})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Value > stats[j].Value
	})

	return stats, total(), processedFiles, skippedFiles
}

func PkgStatistics(_ *malcontent.Config, files *sync.Map) ([]malcontent.StrMetric, int, int) {
	length := smLength(files)
	numBehaviors := 0
	pkgMap := make(map[string]int, length)
	pkg := make(map[string]float64, length)
	files.Range(func(key, value any) bool {
		if key == nil || value == nil {
			return true
		}
		if fr, ok := value.(*malcontent.FileReport); ok {
			if fr.Skipped == "" {
				for _, b := range fr.Behaviors {
					numBehaviors++
					pkgMap[b.ID]++
				}
			}
		}
		return true
	})

	for namespace, count := range pkgMap {
		pkg[namespace] = (float64(count) / float64(numBehaviors)) * 100
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
	stats := make([]malcontent.StrMetric, 0, len(pkg))
	for k, v := range pkg {
		stats = append(stats, malcontent.StrMetric{Key: k, Value: v, Count: pkgMap[k], Total: numBehaviors})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Value > stats[j].Value
	})
	return stats, width, numBehaviors
}

func Statistics(c *malcontent.Config, r *malcontent.Report) error {
	// guard against nil reports
	if r == nil {
		return fmt.Errorf("unexpected nil report")
	}

	riskStats, totalRisks, processedFiles, skippedFiles := RiskStatistics(c, &r.Files)
	pkgStats, width, totalBehaviors := PkgStatistics(c, &r.Files)

	statsSymbol := "📊"
	riskSymbol := "⚠️ "
	pkgSymbol := "📦"
	fmt.Printf("%s Statistics\n", statsSymbol)
	fmt.Println("---")
	fmt.Printf("\033[1;37m%-15s \033[1;37m%s\033[0m\n", "Files Scanned", fmt.Sprintf("%d (%d skipped)", processedFiles, skippedFiles))
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
	fmt.Printf("\033[1;37m%-12s \033[1;37m%10s\033[0m\n", "Number of behaviors", fmt.Sprintf("%d", totalBehaviors))
	fmt.Println("---")
	fmt.Printf("%s Package Behaviors\n", pkgSymbol)
	fmt.Println("---")
	fmt.Printf("\033[1;37m%-*s  \033[1;37m%10s %s\033[0m\n", width, "Namespace", "Percentage", "Count/Total")
	for _, pkg := range pkgStats {
		fmt.Printf("%-*s %10.2f%s %d/%d\n", width, pkg.Key, pkg.Value, "%", pkg.Count, pkg.Total)
	}

	return nil
}
