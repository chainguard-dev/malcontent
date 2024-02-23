package bincapz

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

type Config struct {
	RuleFS     fs.FS
	ScanPaths  []string
	IgnoreTags []string
	MinLevel   int
}

func Scan(c Config) (*Report, error) {
	//	klog.Infof("scan config: %+v", c)
	r := &Report{
		Files: map[string]FileReport{},
	}
	if len(c.IgnoreTags) > 0 {
		r.Filter = strings.Join(c.IgnoreTags, ",")
	}

	yrs, err := compileRules(c.RuleFS)
	klog.V(1).Infof("%d rules loaded", len(yrs.GetRules()))
	if err != nil {
		return r, fmt.Errorf("compile: %w", err)
	}

	for _, p := range c.ScanPaths {
		var mrs yara.MatchRules
		// klog.Infof("scanning: %s", p)
		if err := yrs.ScanFile(p, 0, 0, &mrs); err != nil {
			r.Files[p] = FileReport{Error: fmt.Sprintf("scanfile: %v", err)}
			continue
		}

		fr := fileReport(mrs, c.IgnoreTags, c.MinLevel)
		r.Files[p] = fr
	}

	return r, nil
}
