package action

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/report"
	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

// return a list of files within a path
func findFilesRecursively(root string) ([]string, error) {
	klog.V(1).Infof("finding files in %s ...", root)
	files := []string{}

	err := filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				klog.Errorf("walk %s: %v", path, err)
				return err
			}
			if info.IsDir() {
				return nil
			}
			// False positives in refs file
			if strings.Contains(path, "/.git/") {
				return nil
			}
			files = append(files, path)
			return nil
		})
	return files, err
}

func scanSinglePath(c Config, yrs *yara.Rules, path string) (*bincapz.FileReport, error) {
	var mrs yara.MatchRules
	klog.V(1).Infof("scanning: %s", path)
	kind := programKind(path)
	klog.V(1).Infof("%s kind: %q", path, kind)
	if !c.IncludeDataFiles && kind == "" {
		klog.Infof("not a program: %s", path)
		return &bincapz.FileReport{Skipped: "data file"}, nil
	}

	if err := yrs.ScanFile(path, 0, 0, &mrs); err != nil {
		klog.Infof("skipping %s - %v", path, err)
		return &bincapz.FileReport{Path: path, Error: fmt.Sprintf("scanfile: %v", err)}, nil
	}

	fr := report.Generate(path, mrs, c.IgnoreTags, c.MinLevel)
	if len(fr.Behaviors) == 0 && c.OmitEmpty {
		return nil, nil
	}
	return &fr, nil
}

func Scan(c Config) (*bincapz.Report, error) {
	//	klog.Infof("scan config: %+v", c)
	r := &bincapz.Report{
		Files: map[string]bincapz.FileReport{},
	}
	if len(c.IgnoreTags) > 0 {
		r.Filter = strings.Join(c.IgnoreTags, ",")
	}

	yrs := c.Rules
	klog.Infof("%d rules loaded", len(yrs.GetRules()))

	for _, sp := range c.ScanPaths {
		rp, err := findFilesRecursively(sp)
		if err != nil {
			return nil, fmt.Errorf("find files: %w", err)
		}
		// TODO: support zip files and such
		for _, p := range rp {
			fr, err := scanSinglePath(c, yrs, p)
			if err != nil {
				klog.Errorf("scan path: %v", err)
				continue
			}
			if c.Renderer != nil {
				if err := c.Renderer.File(*fr); err != nil {
					return r, fmt.Errorf("render: %w", err)
				}
			}
			r.Files[p] = *fr
		}
	}

	return r, nil
}
