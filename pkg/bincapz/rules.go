package bincapz

import (
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

func compileRules(root fs.FS) (*yara.Rules, error) {
	yc, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler: %w", err)
	}
	fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		klog.V(2).Infof("path: %v", path)
		if !d.IsDir() && filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar" {
			klog.V(1).Infof("reading %s", path)

			bs, err := fs.ReadFile(root, path)
			if err != nil {
				return fmt.Errorf("readfile: %w", err)
			}
			if err := yc.AddString(string(bs), path); err != nil {
				return fmt.Errorf("yara addfile %s: %w", path, err)
			}

		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	return yc.GetRules()
}
