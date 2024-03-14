package bincapz

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

type Config struct {
	Rules            *yara.Rules
	ScanPaths        []string
	IgnoreTags       []string
	MinLevel         int
	OmitEmpty        bool
	IncludeDataFiles bool
	RenderFunc       RenderFunc
	Output           io.Writer
}

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

func scanSinglePath(c Config, yrs *yara.Rules, path string) (*FileReport, error) {
	var mrs yara.MatchRules
	klog.V(1).Infof("scanning: %s", path)
	kind := programKind(path)
	klog.V(1).Infof("%s kind: %q", path, kind)
	if !c.IncludeDataFiles && kind == "" {
		klog.Infof("not a program: %s", path)
		return &FileReport{Skipped: "data file"}, nil
	}

	if err := yrs.ScanFile(path, 0, 0, &mrs); err != nil {
		klog.Infof("skipping %s - %v", path, err)
		return &FileReport{Path: path, Error: fmt.Sprintf("scanfile: %v", err)}, nil
	}

	fr := fileReport(path, mrs, c.IgnoreTags, c.MinLevel)
	if len(fr.Behaviors) == 0 && c.OmitEmpty {
		return nil, nil
	}
	return &fr, nil
}

func Scan(c Config) (*Report, error) {
	//	klog.Infof("scan config: %+v", c)
	r := &Report{
		Files: map[string]FileReport{},
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
			if c.RenderFunc != nil {
				c.RenderFunc(fr, c.Output, RenderConfig{Title: fmt.Sprintf("✨ %s", p)})
			}
			r.Files[p] = *fr
		}
	}

	return r, nil
}
