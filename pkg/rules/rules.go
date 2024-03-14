package rules

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

var skipFiles = map[string]bool{
	"third_party/Neo23x0/yara/configured_vulns_ext_vars.yar": true,
}

func Compile(root fs.FS, thirdParty bool) (*yara.Rules, error) {
	yc, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler: %w", err)
	}

	// used by 3rd party YARA rules
	vars := []string{"filepath", "filename", "extension", "filetype", "owner"}
	for _, v := range vars {
		if err := yc.DefineVariable(v, v); err != nil {
			return nil, err
		}
	}

	err = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if !thirdParty && strings.Contains(path, "third_party") {
			klog.V(1).Infof("skipping %s (third_party disabled)", path)
			return nil
		}

		klog.V(2).Infof("path: %s", path)
		if skipFiles[path] {
			klog.V(2).Infof("skipping: %s (skipFiles)", path)
			return nil
		}

		if !d.IsDir() && filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar" {
			klog.V(1).Infof("reading %s", path)

			bs, err := fs.ReadFile(root, path)
			if err != nil {
				return fmt.Errorf("readfile: %w", err)
			}

			// Our Yara library likes to panic a lot
			defer func() {
				if err := recover(); err != nil {
					klog.Errorf("recovered from panic loading %s: %v", path, err)
				}
			}()

			if err := yc.AddString(string(bs), path); err != nil {
				return fmt.Errorf("yara addfile %s: %w", path, err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	for _, ycw := range yc.Warnings {
		klog.Warningf("warning from %s: %v", ycw.Rule.Namespace(), ycw.Text)
	}

	for _, yce := range yc.Errors {
		klog.Errorf("error in %s: %v", yce.Rule.Namespace(), yce.Text)
	}

	return yc.GetRules()
}
