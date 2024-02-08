package bincapz

import (
	"fmt"
	"io/fs"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

type Config struct {
	RuleFS     fs.FS
	ScanPaths  []string
	IgnoreTags []string
}

func Scan(c Config) (*Result, error) {
	//	klog.Infof("scan config: %+v", c)
	r := &Result{}
	yrs, err := compileRules(c.RuleFS)
	klog.V(1).Infof("%d rules loaded", len(yrs.GetRules()))
	if err != nil {
		return r, fmt.Errorf("compile: %w", err)
	}

	for _, p := range c.ScanPaths {
		var mrs yara.MatchRules
		// klog.Infof("scanning: %s", p)
		if err := yrs.ScanFile(p, 0, 0, &mrs); err != nil {
			return r, fmt.Errorf("scanfile: %w", err)
		}
		caps := matchToCapabilities(mrs, c.IgnoreTags)
		r.Files = append(r.Files, FileResult{Path: p, Capabilities: caps})
	}

	return r, nil
}
