package action

import (
	"fmt"
	"path/filepath"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"k8s.io/klog/v2"
)

func relFileReport(c Config, path string) (map[string]bincapz.FileReport, error) {
	fromPath := path
	fromConfig := c
	fromConfig.Renderer = nil
	fromConfig.ScanPaths = []string{fromPath}
	fromReport, err := Scan(fromConfig)
	if err != nil {
		return nil, err
	}
	fromRelPath := map[string]bincapz.FileReport{}
	for fname, f := range fromReport.Files {
		if f.Skipped != "" || f.Error != "" {
			continue
		}
		klog.V(1).Infof("report on %q: %+v", fname, f)
		rel, err := filepath.Rel(fromPath, f.Path)
		if err != nil {
			return nil, fmt.Errorf("rel(%q,%q): %w", fromPath, f.Path, err)
		}
		fromRelPath[rel] = f
		klog.Infof("%s = %+v", rel, f)
	}

	return fromRelPath, nil
}

func Diff(c Config) (*bincapz.Report, error) {
	if len(c.ScanPaths) != 2 {
		return nil, fmt.Errorf("diff mode requires 2 paths, you passed in %d path(s)", len(c.ScanPaths))
	}
	from, err := relFileReport(c, c.ScanPaths[0])
	if err != nil {
		return nil, err
	}

	to, err := relFileReport(c, c.ScanPaths[1])
	if err != nil {
		return nil, err
	}

	d := bincapz.DiffReport{
		Added:    map[string]bincapz.FileReport{},
		Removed:  map[string]bincapz.FileReport{},
		Modified: map[string]bincapz.FileReport{},
	}

	// things that appear in the source
	for relPath, fr := range from {
		tr, exists := to[relPath]
		if !exists {
			d.Removed[relPath] = fr
			continue
		}
		rbs := bincapz.FileReport{
			Path:      tr.Path,
			Behaviors: map[string]bincapz.Behavior{},
		}

		// if source behavior is not in the destination
		for key, b := range fr.Behaviors {
			if _, exists := tr.Behaviors[key]; !exists {
				b.DiffRemoved = true
				rbs.Behaviors[key] = b
			}
		}
		d.Modified[relPath] = rbs
	}

	// things that exist in the destination
	for relPath, tr := range to {
		fr, exists := from[relPath]
		if !exists {
			d.Added[relPath] = tr
			continue
		}
		abs := bincapz.FileReport{
			Path:      tr.Path,
			Behaviors: map[string]bincapz.Behavior{},
		}

		// if destination behavior is not in the source
		for key, b := range tr.Behaviors {
			if _, exists := fr.Behaviors[key]; !exists {
				b.DiffAdded = true
				abs.Behaviors[key] = b
			}
		}

		// are there already modified behaviors for this file?
		if _, exists := d.Modified[relPath]; !exists {
			d.Modified[relPath] = abs
		} else {
			for key, b := range abs.Behaviors {
				d.Modified[relPath].Behaviors[key] = b
			}
		}
	}

	klog.V(1).Infof("diff: %+v", d)

	r := &bincapz.Report{
		Diff: d,
	}

	return r, err
}
