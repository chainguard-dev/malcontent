package bincapz

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

type Config struct {
	RuleFS           fs.FS
	ScanPaths        []string
	IgnoreTags       []string
	MinLevel         int
	ThirdPartyRules  bool
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

func Scan(c Config) (*Report, error) {
	//	klog.Infof("scan config: %+v", c)
	r := &Report{
		Files: map[string]FileReport{},
	}
	if len(c.IgnoreTags) > 0 {
		r.Filter = strings.Join(c.IgnoreTags, ",")
	}

	yrs, err := compileRules(c.RuleFS, c.ThirdPartyRules)
	if err != nil {
		return r, fmt.Errorf("YARA rule compilation: %w", err)
	}

	klog.Infof("%d rules loaded", len(yrs.GetRules()))

	for _, sp := range c.ScanPaths {
		rp, err := findFilesRecursively(sp)
		if err != nil {
			return nil, fmt.Errorf("find files: %w", err)
		}
		// TODO: support zip files and such
		for _, p := range rp {
			var mrs yara.MatchRules
			klog.V(1).Infof("scanning: %s", p)
			kind := programKind(p)
			if !c.IncludeDataFiles && kind == "" {
				r.Files[p] = FileReport{Skipped: "data file"}
				klog.Infof("not a program: %s", p)
				continue
			}

			if err := yrs.ScanFile(p, 0, 0, &mrs); err != nil {
				klog.Infof("skipping %s - %v", p, err)
				r.Files[p] = FileReport{Path: p, Error: fmt.Sprintf("scanfile: %v", err)}
				continue
			}

			fr := fileReport(p, mrs, c.IgnoreTags, c.MinLevel)
			if len(fr.Behaviors) == 0 && c.OmitEmpty {
				continue
			}
			r.Files[p] = fr
			if c.RenderFunc != nil {
				c.RenderFunc(&fr, c.Output)
			}
		}
	}

	return r, nil
}
