package bincapz

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

type Config struct {
	RulePaths []string
	ScanPaths []string
}

type Capability struct {
	Rule        string
	Namespace   string
	Description string
	Key         string
	Markers     []string
}

type FileResult struct {
	Path         string
	Capabilities []Capability
}

type Result struct {
	Files []FileResult
}

func compileRules(roots []string) (*yara.Rules, error) {
	yc, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler: %w", err)
	}

	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if strings.Contains(path, "/.") {
				return nil
			}
			klog.V(2).Infof("path: %v", path)

			if !info.IsDir() && filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar" {
				klog.V(1).Infof("reading %s", path)
				f, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("open: %w", err)
				}
				if err := yc.AddFile(f, path); err != nil {
					return fmt.Errorf("yara addfile %s: %w", path, err)
				}

			}

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk: %w", err)
		}
	}
	return yc.GetRules()
}

func namespaceToKey(ns string, rule string) string {
	key := strings.ReplaceAll(ns, "rules/", "")
	key = strings.ReplaceAll(key, ".yara", "")
	return fmt.Sprintf("%s/%s", key, rule)
}

func matchToCapabilities(mrs yara.MatchRules) []Capability {
	caps := []Capability{}
	for _, m := range mrs {
		cap := Capability{
			Rule:      m.Rule,
			Namespace: m.Namespace,
			Key:       namespaceToKey(m.Namespace, m.Rule),
		}
		for _, meta := range m.Metas {
			if meta.Identifier == "description" {
				cap.Description = fmt.Sprintf("%s", meta.Value)
			}

		}
		markers := []string{}
		for _, st := range m.Strings {
			markers = append(markers, strings.Replace(st.Name, "$", "", 1))
		}
		slices.Sort(markers)
		cap.Markers = slices.Compact(markers)
		caps = append(caps, cap)
	}
	klog.V(1).Infof("yara matches: %+v", mrs)
	return caps
}

func Scan(c Config) (*Result, error) {
	r := &Result{}
	yrs, err := compileRules(c.RulePaths)
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
		caps := matchToCapabilities(mrs)
		r.Files = append(r.Files, FileResult{Path: p, Capabilities: caps})
	}

	return r, nil
}
