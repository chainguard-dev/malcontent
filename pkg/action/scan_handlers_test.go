// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
)

const scanTestImageURI = "registry.example/malcontent/scan-test:latest"

func TestExitIfHitOrMissMatchHasBehaviors(t *testing.T) {
	t.Parallel()
	// Map iteration order is unspecified, so many reports without behaviors
	// surround the hit to keep it from simply being the first one visited.
	frs := xsync.NewMap[string, *malcontent.FileReport]()
	for i := range 64 {
		path := fmt.Sprintf("/scan/clean-%02d", i)
		frs.Store(path, &malcontent.FileReport{Path: path})
	}
	hit := scanTestMatchReport(3, "net/http")
	frs.Store(hit.Path, hit)

	match, err := exitIfHitOrMiss(frs, "/scan", true, false, 0)
	if !errors.Is(err, ErrMatchedCondition) {
		t.Fatalf("error: got = %v, want = %v", err, ErrMatchedCondition)
	}
	if match != hit {
		t.Errorf("match: got = %+v, want = %+v", match, hit)
	}
}

func TestInitializeReportFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tags []string
		want string
	}{
		{name: "no ignored tags leave the filter empty", tags: nil, want: ""},
		{name: "a single ignored tag becomes the filter", tags: []string{"harmless"}, want: "harmless"},
		{name: "ignored tags are joined with commas", tags: []string{"harmless", "low"}, want: "harmless,low"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := initializeReport(tt.tags)
			if r.Files == nil {
				t.Fatal("Files: got = nil, want = empty map")
			}
			if r.Filter != tt.want {
				t.Errorf("Filter: got = %q, want = %q", r.Filter, tt.want)
			}
		})
	}
}

func TestRenderMatch(t *testing.T) {
	t.Parallel()
	errRender := errors.New("render failed")

	tests := []struct {
		name         string
		fr           *malcontent.FileReport
		minFileRisk  int
		noRenderer   bool
		renderErr    error
		wantRendered bool
		wantLog      bool
	}{
		{name: "match at the minimum file risk is rendered", fr: scanTestMatchReport(2, "net/http"), minFileRisk: 2, wantRendered: true},
		{name: "match below the minimum file risk is not rendered", fr: scanTestMatchReport(2, "net/http"), minFileRisk: 3},
		{name: "match without behaviors is not rendered", fr: scanTestMatchReport(0)},
		{name: "match without a renderer is not rendered", fr: scanTestMatchReport(2, "net/http"), noRenderer: true},
		{name: "render failure is logged", fr: scanTestMatchReport(2, "net/http"), renderErr: errRender, wantRendered: true, wantLog: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, logs := scanTestLogger()
			rnd := &scanTestRenderer{fileErr: tt.renderErr}
			c := malcontent.Config{MinFileRisk: tt.minFileRisk, Renderer: rnd}
			if tt.noRenderer {
				c.Renderer = nil
			}

			renderMatch(t.Context(), tt.fr, c, logger)

			got := rnd.rendered()
			if len(got) > 1 || (len(got) == 1) != tt.wantRendered {
				t.Fatalf("rendered reports: got = %d, want rendered = %t", len(got), tt.wantRendered)
			}
			if tt.wantRendered && got[0] != tt.fr {
				t.Errorf("rendered report: got = %+v, want = %+v", got[0], tt.fr)
			}
			if gotLog := strings.Contains(logs.String(), "render error"); gotLog != tt.wantLog {
				t.Errorf("render error logged: got = %t, want = %t (logs: %q)", gotLog, tt.wantLog, logs.String())
			}
		})
	}
}

func TestQueuedMatch(t *testing.T) {
	t.Parallel()

	t.Run("empty queue has no match", func(t *testing.T) {
		t.Parallel()
		if m, ok := queuedMatch(make(chan matchResult, 1)); ok {
			t.Errorf("match: got = %+v, want none", m)
		}
	})

	t.Run("queued match is taken from the queue", func(t *testing.T) {
		t.Parallel()
		matchChan := make(chan matchResult, 1)
		want := scanTestMatchReport(3, "net/http")
		matchChan <- matchResult{fr: want, err: ErrMatchedCondition}

		m, ok := queuedMatch(matchChan)
		if !ok || m.fr != want || !errors.Is(m.err, ErrMatchedCondition) {
			t.Errorf("match: got = %+v (found %t), want report %p with %v", m, ok, want, ErrMatchedCondition)
		}
		if got := len(matchChan); got != 0 {
			t.Errorf("queued matches after taking: got = %d, want = 0", got)
		}
	})
}

func TestHandleSingleFileExitConditions(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	fx := newScanTestFixture(t, yrs, rfs)

	tests := []struct {
		name      string
		path      string
		oci       bool
		exitHit   bool
		exitMiss  bool
		trim      []string
		wantErr   bool
		wantMatch bool
		wantKey   string
		wantPath  string
	}{
		{name: "hit with exit-first-hit sends the match", path: fx.hit, exitHit: true, wantErr: true, wantMatch: true},
		{name: "clean file with exit-first-miss sends a miss", path: fx.clean, exitMiss: true, wantErr: true},
		{name: "clean file with exit-first-hit is stored", path: fx.clean, exitHit: true, wantKey: fx.clean, wantPath: fx.clean},
		{name: "hit with exit-first-miss is stored", path: fx.hit, exitMiss: true, wantKey: fx.hit, wantPath: fx.hit},
		{
			name: "OCI image file is stored under the image and its path despite exit-first-hit", path: fx.hit, oci: true, exitHit: true,
			wantKey: scanTestImageURI + " ∴ /app/package.json", wantPath: scanTestImageURI + " ∴ /app/package.json",
		},
		{
			name: "trim prefixes shorten the key and path of a clean file", path: fx.clean, trim: []string{fx.root},
			wantKey: "app/locale.sh", wantPath: "app/locale.sh",
		},
		{
			name: "trim prefixes shorten the key and path of a hit", path: fx.hit, trim: []string{fx.root},
			wantKey: "app/package.json", wantPath: "app/package.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, _ := scanTestLogger()
			r := initializeReport(nil)
			matchChan := make(chan matchResult, 1)
			var once sync.Once
			scanInfo := scanPathInfo{originalPath: fx.root, effectivePath: fx.root}
			if tt.oci {
				scanInfo = scanPathInfo{originalPath: scanTestImageURI, effectivePath: fx.root, ociExtractPath: fx.root, imageURI: scanTestImageURI}
			}
			c := malcontent.Config{
				ExitFirstHit:  tt.exitHit,
				ExitFirstMiss: tt.exitMiss,
				OCI:           tt.oci,
				Rules:         yrs,
				RuleFS:        rfs,
				TrimPrefixes:  tt.trim,
			}

			err := handleSingleFile(t.Context(), tt.path, scanInfo, c, r, matchChan, &once, logger)
			if tt.wantErr {
				if !errors.Is(err, ErrMatchedCondition) {
					t.Fatalf("error: got = %v, want = %v", err, ErrMatchedCondition)
				}
				if got := len(matchChan); got != 1 {
					t.Fatalf("sent matches: got = %d, want = 1", got)
				}
				m := <-matchChan
				if !errors.Is(m.err, ErrMatchedCondition) {
					t.Errorf("sent match error: got = %v, want = %v", m.err, ErrMatchedCondition)
				}
				if got := m.fr != nil; got != tt.wantMatch {
					t.Errorf("sent match has a report: got = %t, want = %t", got, tt.wantMatch)
				}
				if got := r.Files.Size(); got != 0 {
					t.Errorf("stored reports: got = %d, want = 0", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("handleSingleFile: %v", err)
			}
			if got := len(matchChan); got != 0 {
				t.Errorf("sent matches: got = %d, want = 0", got)
			}
			fr, ok := r.Files.Load(tt.wantKey)
			if !ok {
				t.Fatalf("stored keys: got = %v, want key %q", scanTestKeys(r.Files), tt.wantKey)
			}
			if fr.Path != tt.wantPath {
				t.Errorf("Path: got = %q, want = %q", fr.Path, tt.wantPath)
			}
		})
	}
}

func TestHandleSingleFileProcessError(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	root := t.TempDir()
	missing := filepath.Join(root, "app", "missing.sh")

	tests := []struct {
		name    string
		trim    []string
		wantKey string
	}{
		{name: "failed file is recorded under its path", wantKey: missing},
		{name: "failed file is recorded under its trimmed path", trim: []string{root}, wantKey: "app/missing.sh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, _ := scanTestLogger()
			r := initializeReport(nil)
			matchChan := make(chan matchResult, 1)
			var once sync.Once
			c := malcontent.Config{Rules: yrs, RuleFS: rfs, TrimPrefixes: tt.trim}

			// A file that cannot be scanned is recorded as skipped, and the
			// scan goes on.
			err := handleSingleFile(t.Context(), missing, scanPathInfo{originalPath: root, effectivePath: root}, c, r, matchChan, &once, logger)
			if err != nil {
				t.Fatalf("error: got = %v, want = nil", err)
			}
			if got, want := scanTestKeys(r.Files), []string{tt.wantKey}; !slices.Equal(got, want) {
				t.Errorf("stored keys: got = %v, want = %v", got, want)
			}
			if fr, _ := r.Files.Load(tt.wantKey); fr == nil || !strings.HasPrefix(fr.Skipped, errMsgScanFailed+": ") || !strings.Contains(fr.Skipped, syscall.ENOENT.Error()) {
				t.Errorf("report: got = %+v, want one skipped for the missing file", fr)
			}
		})
	}
}

func TestHandleSingleFileRendering(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	fx := newScanTestFixture(t, yrs, rfs)
	errRender := errors.New("render failed")
	baseRisk := map[string]int{fx.hit: fx.hitRisk, fx.clean: 0}

	tests := []struct {
		name          string
		path          string
		minRiskOffset int
		diff          bool
		noRenderer    bool
		renderErr     error
		wantRendered  bool
		wantErr       error
	}{
		{name: "file at the minimum file risk is rendered", path: fx.hit, wantRendered: true},
		{name: "file below the minimum file risk is not rendered", path: fx.hit, minRiskOffset: 1},
		{name: "file without behaviors is not rendered", path: fx.clean},
		{name: "diff report suppresses per-file rendering", path: fx.hit, diff: true},
		{name: "missing renderer skips rendering", path: fx.hit, noRenderer: true},
		{name: "render failure is returned", path: fx.hit, renderErr: errRender, wantRendered: true, wantErr: errRender},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, _ := scanTestLogger()
			r := initializeReport(nil)
			if tt.diff {
				r.Diff = &malcontent.DiffReport{}
			}
			matchChan := make(chan matchResult, 1)
			var once sync.Once
			rnd := &scanTestRenderer{fileErr: tt.renderErr}
			c := malcontent.Config{MinFileRisk: baseRisk[tt.path] + tt.minRiskOffset, Renderer: rnd, Rules: yrs, RuleFS: rfs}
			if tt.noRenderer {
				c.Renderer = nil
			}

			err := handleSingleFile(t.Context(), tt.path, scanPathInfo{originalPath: fx.root, effectivePath: fx.root}, c, r, matchChan, &once, logger)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error: got = %v, want = %v", err, tt.wantErr)
			}
			if _, ok := r.Files.Load(tt.path); !ok {
				t.Errorf("stored keys: got = %v, want key %q", scanTestKeys(r.Files), tt.path)
			}
			if got := len(rnd.rendered()) > 0; got != tt.wantRendered {
				t.Errorf("rendered: got = %t, want = %t", got, tt.wantRendered)
			}
		})
	}
}

// scanTestArchive writes a zip holding the hit and clean fixtures under app/.
func scanTestArchive(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.zip")
	buildZipFile(t, path, map[string][]byte{
		"app/locale.sh":    []byte(scanTestLocaleScript),
		"app/package.json": readTestFile(t, scanTestNPMFixture),
	})
	return path
}

func TestProcessPathArchiveExitConditions(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	archivePath := scanTestArchive(t)
	archiveDir := filepath.Dir(archivePath)
	inArchive := func(archive string) []string {
		return []string{archive + " ∴ /app/locale.sh", archive + " ∴ /app/package.json"}
	}

	tests := []struct {
		name     string
		oci      bool
		exitHit  bool
		exitMiss bool
		trim     []string
		wantErr  bool
		wantKeys []string
	}{
		{name: "archive with a hit and exit-first-hit sends the match", exitHit: true, wantErr: true},
		// Each file of an archive is judged on its own, as walked files are.
		{name: "archive with a clean file meets exit-first-miss on that file", exitMiss: true, wantErr: true},
		{name: "archive files are stored under archive and entry paths", wantKeys: inArchive(archivePath)},
		{name: "OCI archive is stored under the image and its path despite exit-first-hit", oci: true, exitHit: true, wantKeys: inArchive(scanTestImageURI + " ∴ /bundle.zip")},
		{name: "trim prefixes shorten the archive path in entry keys", trim: []string{archiveDir}, wantKeys: inArchive("bundle.zip")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, _ := scanTestLogger()
			r := initializeReport(nil)
			matchChan := make(chan matchResult, 1)
			var once sync.Once
			scanInfo := scanPathInfo{originalPath: archiveDir, effectivePath: archiveDir}
			if tt.oci {
				scanInfo = scanPathInfo{originalPath: scanTestImageURI, effectivePath: archiveDir, ociExtractPath: archiveDir, imageURI: scanTestImageURI}
			}
			c := malcontent.Config{
				ExitFirstHit:  tt.exitHit,
				ExitFirstMiss: tt.exitMiss,
				OCI:           tt.oci,
				Rules:         yrs,
				RuleFS:        rfs,
				TrimPrefixes:  tt.trim,
			}

			err := processPath(t.Context(), archivePath, scanInfo, c, r, matchChan, &once, logger)
			if tt.wantErr {
				if !errors.Is(err, ErrMatchedCondition) {
					t.Fatalf("error: got = %v, want = %v", err, ErrMatchedCondition)
				}
				if got := len(matchChan); got != 1 {
					t.Fatalf("sent matches: got = %d, want = 1", got)
				}
				// A hit is sent with its report; a miss without one.
				if m := <-matchChan; tt.exitHit != (m.fr != nil && len(m.fr.Behaviors) > 0) {
					t.Errorf("sent match: got = %+v, want a report with behaviors = %t", m.fr, tt.exitHit)
				}
				if got := r.Files.Size(); got != 0 {
					t.Errorf("stored reports: got = %d, want = 0", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("processPath: %v", err)
			}
			if got := len(matchChan); got != 0 {
				t.Errorf("sent matches: got = %d, want = 0", got)
			}
			if got := scanTestKeys(r.Files); !slices.Equal(got, tt.wantKeys) {
				t.Errorf("stored keys: got = %v, want = %v", got, tt.wantKeys)
			}
			// Each key is the entry's display path.
			r.Files.Range(func(key string, fr *malcontent.FileReport) bool {
				if fr.Path != key {
					t.Errorf("Path for key %q: got = %q, want = %q", key, fr.Path, key)
				}
				return true
			})
		})
	}
}

func TestProcessPathArchiveRendering(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	archivePath := scanTestArchive(t)
	scanInfo := scanPathInfo{originalPath: filepath.Dir(archivePath), effectivePath: filepath.Dir(archivePath)}
	wantKeys := []string{archivePath + " ∴ /app/locale.sh", archivePath + " ∴ /app/package.json"}
	errRender := errors.New("render failed")

	baseline := initializeReport(nil)
	logger, _ := scanTestLogger()
	if err := processPath(t.Context(), archivePath, scanInfo, malcontent.Config{Rules: yrs, RuleFS: rfs}, baseline, make(chan matchResult, 1), &sync.Once{}, logger); err != nil {
		t.Fatalf("processPath: %v", err)
	}
	hit, ok := baseline.Files.Load(wantKeys[1])
	if !ok || len(hit.Behaviors) == 0 || hit.RiskScore < 1 {
		t.Fatalf("fixture precondition: archive hit: got = %+v, want a report with behaviors and risk >= 1", hit)
	}

	tests := []struct {
		name         string
		zeroMinRisk  bool
		riskOffset   int
		diff         bool
		noRenderer   bool
		renderErr    error
		wantRendered int
		wantLog      bool
	}{
		{name: "entry at the minimum file risk is rendered", wantRendered: 1},
		{name: "entry below the minimum file risk is not rendered", riskOffset: 1},
		{name: "entry without behaviors is not rendered", zeroMinRisk: true, wantRendered: 1},
		{name: "diff report suppresses per-entry rendering", diff: true},
		{name: "missing renderer skips rendering", noRenderer: true},
		{name: "render failure is logged and the archive is stored", renderErr: errRender, wantRendered: 1, wantLog: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, logs := scanTestLogger()
			r := initializeReport(nil)
			if tt.diff {
				r.Diff = &malcontent.DiffReport{}
			}
			rnd := &scanTestRenderer{fileErr: tt.renderErr}
			c := malcontent.Config{MinFileRisk: hit.RiskScore + tt.riskOffset, Renderer: rnd, Rules: yrs, RuleFS: rfs}
			if tt.zeroMinRisk {
				c.MinFileRisk = 0
			}
			if tt.noRenderer {
				c.Renderer = nil
			}

			if err := processPath(t.Context(), archivePath, scanInfo, c, r, make(chan matchResult, 1), &sync.Once{}, logger); err != nil {
				t.Fatalf("processPath: %v", err)
			}
			if got := scanTestKeys(r.Files); !slices.Equal(got, wantKeys) {
				t.Errorf("stored keys: got = %v, want = %v", got, wantKeys)
			}
			got := rnd.rendered()
			if len(got) != tt.wantRendered {
				t.Fatalf("rendered reports: got = %d, want = %d", len(got), tt.wantRendered)
			}
			for _, fr := range got {
				if !strings.HasSuffix(fr.Path, "/app/package.json") {
					t.Errorf("rendered Path: got = %q, want the archive hit", fr.Path)
				}
			}
			logged := logs.String()
			if gotLog := strings.Contains(logged, "render error"); gotLog != tt.wantLog {
				t.Errorf("render error logged: got = %t, want = %t (logs: %q)", gotLog, tt.wantLog, logged)
			}
			if strings.Contains(logged, "remove ") {
				t.Errorf("logs: got = %q, want no extraction cleanup failure", logged)
			}
		})
	}
}

func TestKeepOnlyMatch(t *testing.T) {
	t.Parallel()
	errMatch := fmt.Errorf("/scan/root %w", ErrMatchedCondition)

	tests := []struct {
		name     string
		fr       *malcontent.FileReport
		wantKeys []string
	}{
		{name: "match replaces the stored reports under its display path", fr: &malcontent.FileReport{Path: "/scan/root/bin/tool"}, wantKeys: []string{"/scan/root/bin/tool"}},
		{name: "archive entry match is stored under its display path", fr: &malcontent.FileReport{Path: "bundle.zip ∴ /bin/tool"}, wantKeys: []string{"bundle.zip ∴ /bin/tool"}},
		{name: "miss clears the stored reports"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := initializeReport(nil)
			r.Files.Store("/scan/root/bin/other", &malcontent.FileReport{Path: "/scan/root/bin/other"})

			err := keepOnlyMatch(r, matchResult{fr: tt.fr, err: errMatch})
			if !errors.Is(err, errMatch) {
				t.Errorf("error: got = %v, want = %v", err, errMatch)
			}
			if got := scanTestKeys(r.Files); !slices.Equal(got, tt.wantKeys) {
				t.Errorf("stored keys: got = %v, want = %v", got, tt.wantKeys)
			}
			for _, key := range tt.wantKeys {
				if fr, ok := r.Files.Load(key); ok && fr.Path != key {
					t.Errorf("Path for key %q: got = %q, want = %q", key, fr.Path, key)
				}
			}
		})
	}
}

func TestCleanupOCIPathRemovesExtractedImage(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "image")
	scanTestWriteFile(t, filepath.Join(dir, "etc", "profile.d", "locale.sh"), []byte(scanTestLocaleScript))
	logger, logs := scanTestLogger()

	cleanupOCIPath(dir, logger)

	if _, err := file.StatIn(tmp, "image"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stat extracted image: got = %v, want = %v", err, fs.ErrNotExist)
	}
	if got := logs.String(); got != "" {
		t.Errorf("logs: got = %q, want = empty", got)
	}
}

func TestHandleOCIResults(t *testing.T) {
	t.Parallel()
	hitPath := scanTestImageURI + " ∴ /app/package.json"
	cleanPath := scanTestImageURI + " ∴ /app/locale.sh"

	tests := []struct {
		name        string
		withHit     bool
		exitHit     bool
		exitMiss    bool
		minFileRisk int
		noRenderer  bool
		wantErr     bool
		wantKeys    []string
	}{
		{name: "hit at the minimum file risk ends the scan with only the hit", withHit: true, exitHit: true, minFileRisk: 3, wantErr: true, wantKeys: []string{hitPath}},
		{name: "hit below the minimum file risk is no hit", withHit: true, exitHit: true, minFileRisk: 4, wantKeys: []string{cleanPath, hitPath}},
		{name: "hit below the minimum file risk is a miss", withHit: true, exitMiss: true, minFileRisk: 4, wantErr: true},
		{name: "hit without a renderer ends the scan", withHit: true, exitHit: true, noRenderer: true, wantErr: true, wantKeys: []string{hitPath}},
		{name: "image without hits ends the scan under exit-first-miss with no files", exitMiss: true, wantErr: true},
		{name: "image with a hit completes under exit-first-miss", withHit: true, exitMiss: true, wantKeys: []string{cleanPath, hitPath}},
		{name: "image with a hit completes without exit flags", withHit: true, wantKeys: []string{cleanPath, hitPath}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := initializeReport(nil)
			r.Files.Store(cleanPath, &malcontent.FileReport{Path: cleanPath})
			if tt.withHit {
				hit := scanTestMatchReport(3, "net/http")
				hit.Path = hitPath
				r.Files.Store(hitPath, hit)
			}
			rnd := &scanTestRenderer{}
			c := malcontent.Config{ExitFirstHit: tt.exitHit, ExitFirstMiss: tt.exitMiss, MinFileRisk: tt.minFileRisk, Renderer: rnd}
			if tt.noRenderer {
				c.Renderer = nil
			}

			err := handleOCIResults(scanTestImageURI, r.Files, r, c)
			if got := errors.Is(err, ErrMatchedCondition); got != tt.wantErr {
				t.Fatalf("ends the scan: got = %t (error %v), want = %t", got, err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), scanTestImageURI) {
				t.Errorf("error: got = %v, want it to name %q", err, scanTestImageURI)
			}
			if got := scanTestKeys(r.Files); !slices.Equal(got, tt.wantKeys) {
				t.Errorf("stored keys: got = %v, want = %v", got, tt.wantKeys)
			}
			// Image files are rendered while they are scanned, not again here.
			if got := len(rnd.rendered()); got != 0 {
				t.Errorf("rendered reports: got = %d, want = 0", got)
			}
		})
	}
}

func TestProcessPathsEvaluatesOCIImageAsWhole(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	fx := newScanTestFixture(t, yrs, rfs)
	hitPath := scanTestImageURI + " ∴ /app/package.json"

	allKeys := []string{scanTestImageURI + " ∴ /app/locale.sh", hitPath}
	tests := []struct {
		name        string
		paths       []string
		exitHit     bool
		exitMiss    bool
		minFileRisk int
		wantErr     bool
		wantKeys    []string
	}{
		{name: "image with a hit ends the scan under exit-first-hit", paths: []string{fx.hit, fx.clean}, exitHit: true, wantErr: true, wantKeys: []string{hitPath}},
		{name: "image whose hit is below the minimum file risk completes under exit-first-hit", paths: []string{fx.hit, fx.clean}, exitHit: true, minFileRisk: fx.hitRisk + 1, wantKeys: allKeys},
		{name: "image without a hit ends the scan under exit-first-miss", paths: []string{fx.clean}, exitMiss: true, wantErr: true},
		{name: "image whose hit is below the minimum file risk ends the scan under exit-first-miss", paths: []string{fx.hit, fx.clean}, exitMiss: true, minFileRisk: fx.hitRisk + 1, wantErr: true},
		{name: "image with a hit completes without exit flags", paths: []string{fx.hit, fx.clean}, minFileRisk: fx.hitRisk + 1, wantKeys: allKeys},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, _ := scanTestLogger()
			r := initializeReport(nil)
			matchChan := make(chan matchResult, 1)
			var once sync.Once
			scanInfo := scanPathInfo{originalPath: scanTestImageURI, effectivePath: fx.root, ociExtractPath: fx.root, imageURI: scanTestImageURI}
			// Exit criteria judge what the minimum file risk leaves.
			c := malcontent.Config{
				Concurrency:   2,
				ExitFirstHit:  tt.exitHit,
				ExitFirstMiss: tt.exitMiss,
				MinFileRisk:   tt.minFileRisk,
				OCI:           true,
				Rules:         yrs,
				RuleFS:        rfs,
			}

			err := processTestPaths(t, slices.Clone(tt.paths), scanInfo, c, r, matchChan, &once, logger)
			if got := errors.Is(err, ErrMatchedCondition); got != tt.wantErr {
				t.Fatalf("ends the scan: got = %t (error %v), want = %t", got, err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), scanTestImageURI) {
				t.Errorf("error: got = %v, want it to name %q", err, scanTestImageURI)
			}
			if got := scanTestKeys(r.Files); !slices.Equal(got, tt.wantKeys) {
				t.Errorf("stored keys: got = %v, want = %v", got, tt.wantKeys)
			}
		})
	}
}

func TestProcessPathsExitMatchIsTheOnlyResult(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	fx := newScanTestFixture(t, yrs, rfs)

	tests := []struct {
		name        string
		categories  []string
		minFileRisk int
		wantMatch   bool
	}{
		{name: "match is stored and rendered once", wantMatch: true},
		{name: "a hit the category filter leaves without behaviors is no match", categories: []string{"scan-test-no-such-category"}},
		{name: "a hit below the minimum file risk is no match", minFileRisk: fx.hitRisk + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, _ := scanTestLogger()
			r := initializeReport(nil)
			matchChan := make(chan matchResult, 1)
			var once sync.Once
			rnd := &scanTestRenderer{}
			c := malcontent.Config{Concurrency: 1, ExitFirstHit: true, MinFileRisk: tt.minFileRisk, Renderer: rnd, RuleCategories: tt.categories, Rules: yrs, RuleFS: rfs}

			paths := []string{fx.clean, fx.hit}
			err := processTestPaths(t, paths, scanPathInfo{originalPath: fx.root, effectivePath: fx.root}, c, r, matchChan, &once, logger)
			if got := errors.Is(err, ErrMatchedCondition); got != tt.wantMatch {
				t.Fatalf("match: got = %t (error %v), want = %t", got, err, tt.wantMatch)
			}
			if !tt.wantMatch {
				// The scan finished: both files are stored and nothing left
				// to show is rendered.
				if got, want := scanTestKeys(r.Files), []string{fx.clean, fx.hit}; !slices.Equal(got, want) {
					t.Errorf("stored keys: got = %v, want = %v", got, want)
				}
				if got := rnd.rendered(); len(got) != 0 {
					t.Errorf("rendered reports: got = %d, want = 0", len(got))
				}
				return
			}
			if got, want := scanTestKeys(r.Files), []string{fx.hit}; !slices.Equal(got, want) {
				t.Fatalf("stored keys: got = %v, want = %v", got, want)
			}
			fr, _ := r.Files.Load(fx.hit)
			if got := rnd.rendered(); len(got) != 1 || got[0] != fr {
				t.Errorf("rendered reports: got = %d, want the match rendered once", len(got))
			}
		})
	}
}

func TestProcessPathScansAPathWithoutAWalkRootAsASingleFile(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	path := filepath.Join(t.TempDir(), "missing")
	scanInfo := scanPathInfo{originalPath: path, effectivePath: path}
	c := malcontent.Config{Rules: yrs, RuleFS: rfs}
	logger, _ := scanTestLogger()

	want := initializeReport(nil)
	wantErr := handleSingleFile(t.Context(), path, scanInfo, c, want, make(chan matchResult, 1), &sync.Once{}, logger)
	got := initializeReport(nil)
	err := processPath(t.Context(), path, scanInfo, c, got, make(chan matchResult, 1), &sync.Once{}, logger)
	if fmt.Sprint(err) != fmt.Sprint(wantErr) || got.Files.Size() != want.Files.Size() {
		t.Errorf("processPath(%q): got = (%d reports, %v), want = (%d, %v)", path, got.Files.Size(), err, want.Files.Size(), wantErr)
	}
}
