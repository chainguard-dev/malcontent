package main

import (
	"encoding/json"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/bincapz/pkg/action"
	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/google/go-cmp/cmp"
)

var testDataRoot = "testdata"

func TestJSON(t *testing.T) {
	fileSystem := os.DirFS(testDataRoot)

	fs.WalkDir(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Fatal(err)
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		name := strings.ReplaceAll(path, ".json", "")
		jsonPath := path
		binPath := filepath.Join(testDataRoot, name)

		t.Run(name, func(t *testing.T) {
			td, err := fs.ReadFile(fileSystem, jsonPath)
			if err != nil {
				t.Fatalf("testdata read failed: %v", err)
			}

			var want bincapz.Report
			if err := json.Unmarshal(td, &want); err != nil {
				t.Fatalf("testdata unmarshal: %v", err)
			}

			bc := action.Config{
				// defined in bincapz.go
				//				RuleFS:     ruleFs,
				ScanPaths:  []string{binPath},
				IgnoreTags: []string{"harmless"},
			}

			got, err := action.Scan(bc)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}

			if diff := cmp.Diff(*got, want); diff != "" {
				t.Errorf("unexpected diff: %s", diff)
			}

		})
		return nil
	})
}
