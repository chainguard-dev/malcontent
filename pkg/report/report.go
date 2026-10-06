// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/rules"

	yarax "github.com/VirusTotal/yara-x/go"
)

const NAME string = "malcontent"

const (
	INVALID int = iota - 1
	HARMLESS
	LOW
	MEDIUM
	HIGH
	CRITICAL
)

// String forms of the risk levels. Kept as package-level constants so
// callers (production and tests) can reference the same source of truth
// without repeating the literal.
const (
	LevelNONE     = "NONE"
	LevelLOW      = "LOW"
	LevelMEDIUM   = "MEDIUM"
	LevelHIGH     = "HIGH"
	LevelCRITICAL = "CRITICAL"
)

// Well-known rule-tag and file-extension literals treated specially by
// the report pipeline. Grouped here so callers avoid repeating the raw
// string across files.
const (
	tagHarmless  = "harmless" // YARA tag treated as HARMLESS risk in Levels
	extClass     = "class"    // Java bytecode extension, aliased to jar/java
	extPyc       = "pyc"      // Python bytecode extension, aliased to py
	testJunkWord = "test"     // filtered from the head of long third-party rule names
)

// Map to handle RiskScore -> RiskLevel conversions.
var RiskLevels = map[int]string{
	INVALID:  LevelNONE,     // invalid: unmodified initial value which should not happen
	HARMLESS: LevelNONE,     // harmless: common to all executables, no system impact
	LOW:      LevelLOW,      // undefined: low impact, common to good and bad executables
	MEDIUM:   LevelMEDIUM,   // notable: may have impact, but common
	HIGH:     LevelHIGH,     // suspicious: uncommon, but could be legit
	CRITICAL: LevelCRITICAL, // critical: certainly malware
}

// yaraForge has some very, very long rule names.
var yaraForgeJunkWords = map[string]struct{}{
	".yara":             {},
	"0":                 {},
	"1":                 {},
	"2":                 {},
	"apt":               {},
	"artefacts":         {},
	"artifacts":         {},
	"base":              {},
	"big":               {},
	"controller":        {},
	"dynamic":           {},
	"encoded":           {},
	"exe":               {},
	"forensic":          {},
	"forensicartifacts": {},
	"generic":           {},
	"greyware":          {},
	"hunting":           {},
	"indicator":         {},
	"keyword":           {},
	"linux":             {},
	"lnx":               {},
	"m":                 {},
	"mac":               {},
	"macos":             {},
	"mal":               {},
	"malware":           {},
	"offensive":         {},
	"osx":               {},
	"sig":               {},
	"small":             {},
	"suspicious":        {},
	"tool":              {},
	"trojan":            {},
	"unix":              {},
	"YARAForge":         {},
}

// authorWithURLRe matches "Arnim Rupp (https://github.com/ruppde)"
var (
	authorWithURLRe        = regexp.MustCompile(`(.*?) \((http.*)\)`)
	threatHuntingKeywordRe = regexp.MustCompile(`Detection patterns for the tool '(.*)' taken from the ThreatHunting-Keywords github project`)
	// dateRe matches a whole rule-name word that is a month followed by a day
	// or two-digit year, a four-digit year, or a year and month (jun17,
	// may2022, apr202004). It is anchored so words that merely contain three
	// letters and a digit, such as base64exec or gen2, are kept.
	dateRe = regexp.MustCompile(`^(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)(?:\d{1,2}|\d{4}|\d{6})$`)
)

// Map to handle RiskLevel -> RiskScore conversions.
var Levels = map[string]int{
	"ignore":     INVALID,
	"none":       INVALID,
	tagHarmless:  HARMLESS,
	"low":        LOW,
	"notable":    MEDIUM,
	"medium":     MEDIUM,
	"suspicious": HIGH,
	"weird":      HIGH,
	"high":       HIGH,
	"crit":       CRITICAL,
	"critical":   CRITICAL,
}

func thirdPartyKey(path string, rule string) string {
	// include the directory; a path without "yara/" leaves afterYara empty,
	// which has no subdirectory
	_, afterYara, _ := strings.Cut(path, "yara/")
	subDir, _, found := strings.Cut(afterYara, "/")
	if !found || subDir == "" || strings.Contains(subDir, ".yara") {
		return ""
	}

	// ELASTIC_Linux_Trojan_Gafgyt_E4A1982B
	// Start with words from the rule name, not including subDir yet. Split
	// always returns at least one word.
	words := strings.Split(strings.ToLower(rule), "_")

	// strip off the last word if it's a hex key or hash of any length
	if isHexWord(words[len(words)-1]) {
		words = words[:len(words)-1]
	}

	keepWords := make([]string, 0, len(words))
	subDirLower := strings.ToLower(subDir)

	for x, w := range words {
		// ends with a date or empty
		if (x == len(words)-1 && dateRe.MatchString(w)) || w == "" {
			continue
		}

		// Filter out junk words and the subdirectory name
		if _, junk := yaraForgeJunkWords[w]; !junk && w != subDirLower {
			keepWords = append(keepWords, w)
		}
	}

	// Additionally filter testJunkWord from the beginning if there are other words
	if len(keepWords) > 1 && keepWords[0] == testJunkWord {
		keepWords = keepWords[1:]
	}

	// If we filtered everything, keep at least the first word that's not the subdir
	if len(keepWords) == 0 {
		for x := 0; x < len(words); x++ {
			if words[x] != "" && !dateRe.MatchString(words[x]) && words[x] != subDirLower {
				keepWords = append(keepWords, words[x])
				break
			}
		}
	}

	// Max 3 words in the rule name (source is separate), except for sources
	// whose rule identifiers are already concise and meaningful (e.g. GuardDog),
	// where truncation would collapse distinct rules (..._base64exec, ..._chr,
	// ...) into one key and lose findings during dedup.
	if _, keepAll := severityDrivenSources[subDirLower]; !keepAll {
		keepWords = keepWords[:min(len(keepWords), 3)]
	}

	// Fix name for https://github.com/Neo23x0/signature-base within YARAForge
	src := strings.Replace(subDir, "signature", "sig_base", 1)

	// All keepWords are part of the rule name
	ruleName := keepWords

	return strings.TrimRight(fmt.Sprintf("3P/%s/%s", src, strings.Join(ruleName, "_")), "/")
}

// isHexWord reports whether w is a non-empty run of lowercase hex digits, such
// as the key, hash, or certificate serial that ends many third-party rule names.
func isHexWord(w string) bool {
	return w != "" && strings.Trim(w, "0123456789abcdef") == ""
}

// thirdParty reports whether a rule originates from a third-party feed.
// A rule is third-party iff its source path begins with "yara/".
func thirdParty(src string) bool {
	return strings.HasPrefix(src, "yara/")
}

func isValidURL(s string) bool {
	_, err := url.Parse(s)
	return err == nil
}

func generateKey(src string, rule string) string {
	if thirdParty(src) {
		return thirdPartyKey(src, rule)
	}

	key := strings.ReplaceAll(src, "-", "_")
	for strings.Contains(key, ".yara") {
		key = strings.ReplaceAll(key, ".yara", "")
	}

	// Reduce stutter: if the rule is prefixed with the directory name, remove the prefix
	dirParts := strings.Split(key, "/")
	// ID's generally follow: `<namespace>/<resource>/<technique>`
	if len(dirParts) > 1 {
		// namespaces can have dashes, like 'anti-static'
		dirParts[0] = strings.ReplaceAll(dirParts[0], "_", "-")

		// the last two parts are the resource and the technique (potentially one in the same)
		rsrc := dirParts[len(dirParts)-2]
		tech := strings.ReplaceAll(dirParts[len(dirParts)-1], rsrc, "")
		tech = strings.ReplaceAll(tech, "__", "_")
		dirParts[len(dirParts)-1] = strings.Trim(tech, "_")
	}

	result := strings.TrimRight(strings.Join(dirParts, "/"), "/")
	for strings.Contains(result, ".yara") {
		result = strings.ReplaceAll(result, ".yara", "")
	}
	return strings.TrimRight(result, "/")
}

// ruleDeclRE matches a YARA rule declaration at the start of a line.
// Anchored at column zero so commented or quoted occurrences of "rule"
// inside a string literal do not match. Bounded `\w+` has no backtracking.
var ruleDeclRE = regexp.MustCompile(`^rule\s+(\w+)`)

const (
	// ruleIndexMaxEntries bounds the size of ruleLineIndex. The rules tree
	// is in the low thousands; the cap is a safety margin that guards
	// against pathological embed contents.
	ruleIndexMaxEntries = 4096
)

var (
	ruleLineIndexOnce sync.Once
	// ruleLineIndex stays nil, indexing nothing, when it fails to build.
	ruleLineIndex map[string]int
)

// buildRuleLineIndex walks fsys, mapping "<src>:<rule_name>" to the 1-based
// line of each rule declaration in its .yara and .yar files. ruleLine builds
// it from the embedded rules.FS exactly once and caches it in ruleLineIndex.
func buildRuleLineIndex(fsys fs.FS) (map[string]int, error) {
	idx := make(map[string]int, 2048)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yara" && ext != ".yar" {
			return nil
		}
		bs, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		scanner := bufio.NewScanner(bytes.NewReader(bs))
		// YARA rules can have long string literals; bump the buffer.
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Bytes()
			m := ruleDeclRE.FindSubmatch(line)
			if m == nil {
				continue
			}
			name := string(m[1])
			key := path + ":" + name
			if _, dup := idx[key]; dup {
				continue
			}
			idx[key] = lineNo
			if len(idx) > ruleIndexMaxEntries {
				return fmt.Errorf("rule index exceeds cap %d", ruleIndexMaxEntries)
			}
		}
		return scanner.Err()
	})
	if err != nil {
		return nil, err
	}
	return idx, nil
}

// ruleLine returns the 1-based line of the declaration for (src, rule) in
// the embedded rules tree. The second value is false when the pair is not
// indexed or when the index failed to build.
func ruleLine(src, rule string) (int, bool) {
	ruleLineIndexOnce.Do(func() {
		ruleLineIndex, _ = buildRuleLineIndex(rules.FS)
	})
	line, ok := ruleLineIndex[src+":"+rule]
	return line, ok
}

// generateRuleURL returns the GitHub URL of rule's declaration in src at the
// git ref, which release.ResolveRuleURLCommit supplies. An empty ref means the
// main branch.
func generateRuleURL(ref string, src string, rule string) string {
	if ref == "" {
		ref = "main"
	}
	// third_party rules live under third_party/, not rules/. The embedded
	// rules.FS only covers the first-party tree, so ruleLine misses for
	// third_party src and the name-anchor fallback applies.
	pathPrefix := "rules"
	if thirdParty(src) {
		pathPrefix = "third_party"
	}
	if line, ok := ruleLine(src, rule); ok {
		return fmt.Sprintf("https://github.com/chainguard-dev/malcontent/blob/%s/%s/%s#L%d", ref, pathPrefix, src, line)
	}
	return fmt.Sprintf("https://github.com/chainguard-dev/malcontent/blob/%s/%s/%s#%s", ref, pathPrefix, src, rule)
}

func ignoreMatch(tags []string, ignoreTags map[string]struct{}) bool {
	for _, t := range tags {
		if _, ok := ignoreTags[t]; ok {
			return true
		}
	}
	return false
}

// nsSecondSegment returns the substring between the first and second '/'
// of ns, or "" if ns has fewer than two '/'-separated segments. The
// result is a sub-slice of the input; no allocation is performed.
func nsSecondSegment(ns string) string {
	// Without a '/', rest is empty, and so is its first segment.
	_, rest, _ := strings.Cut(ns, "/")
	seg, _, _ := strings.Cut(rest, "/")
	return seg
}

// containsFoldASCII reports whether haystack contains needle under ASCII
// case folding, without allocating. needle must already be lowercase
// ASCII; all bytes outside [A-Z] match exactly.
func containsFoldASCII(haystack, needle string) bool {
	// A needle longer than haystack has no start position, and an empty
	// needle matches at the first one.
next:
	for i := range len(haystack) - len(needle) + 1 {
		for j := range len(needle) {
			c := haystack[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needle[j] {
				continue next
			}
		}
		return true
	}
	return false
}

func behaviorRisk(ns string, rule string, tags []string) int {
	risk := LOW

	if thirdParty(ns) {
		risk = HIGH

		switch nsSecondSegment(ns) {
		case "JPCERT", "YARAForge", "bartblaze", "huntress", "elastic":
			risk = CRITICAL
			if containsFoldASCII(ns, "generic") || containsFoldASCII(rule, "generic") {
				risk = HIGH
			}
		}

		if containsFoldASCII(ns, "keyword") || containsFoldASCII(rule, "keyword") {
			risk = MEDIUM
		}
	}

	if strings.Contains(ns, "combo/") {
		risk = MEDIUM
	}

	for _, tag := range tags {
		if r, ok := Levels[tag]; ok {
			return r
		}
	}

	return risk
}

// fixURL fixes badly formed URLs.
func fixURL(s string) string {
	// YARAforge forgets to encode spaces, but encodes everything else
	return strings.ReplaceAll(s, " ", "%20")
}

// mungeDescription shortens verbose descriptions.
func mungeDescription(s string) string {
	// in: Detection patterns for the tool 'Nsight RMM' taken from the ThreatHunting-Keywords github project
	// out: references "Nsight RMM" tool
	if m := threatHuntingKeywordRe.FindStringSubmatch(s); m != nil {
		return fmt.Sprintf("references %q tool", m[1])
	}
	return s
}

// TrimPrefixes removes the specified prefix from a given path for the purposes of sample test data generation.
// This function will only be used via the refresh package.
func TrimPrefixes(path string, prefixes []string) string {
	for _, prefix := range prefixes {
		if prefix == "/private" {
			return strings.TrimPrefix(path, prefix)
		}

		// Strip ./ prefix; an empty prefix trims nothing
		prefix = strings.TrimPrefix(prefix, "./")
		if prefix == "" {
			continue
		}

		// Try matching as-is first (handles both relative and absolute)
		if trimmed, ok := strings.CutPrefix(path, prefix); ok {
			return strings.TrimPrefix(trimmed, string(filepath.Separator))
		}

		// If prefix is relative but path is absolute, try with leading /
		if rest, abs := strings.CutPrefix(path, "/"); abs && !strings.HasPrefix(prefix, "/") {
			if trimmed, ok := strings.CutPrefix(rest, prefix); ok {
				return strings.TrimPrefix(trimmed, string(filepath.Separator))
			}
		}
	}
	return path
}

// skipMatch determines whether to avoid processing a rule match.
func skipMatch(ignoreMalcontent, override, scan bool, risk, threshold, highestRisk int) bool {
	if risk == INVALID {
		return true
	}
	// The malcontent rule is classified as harmless
	// A !ignoreMalcontent condition will prevent the rule from being filtered
	if !scan && risk < threshold && !ignoreMalcontent && !override {
		return true
	}
	// If running a scan as opposed to an analyze,
	// drop any matches that fall below the highest risk
	return scan && risk < highestRisk && !ignoreMalcontent && !override
}

// skipScanFile determines whether a scanned file should
// be ignored when running a scan and the file's risk is below HIGH.
func skipScanFile(scan bool, overallRiskScore int) bool {
	if scan && overallRiskScore < HIGH {
		return true
	}
	return false
}

// applyCriticalUpgrade evaluates whether to apply a risk increase
// depending on c.QuantityIncreasesRisk, the file's high behavior count, and the file's size.
func applyCriticalUpgrade(ctx context.Context, quantityIncreasesRisk bool, highCount int, overallRiskScore int, size int64) bool {
	// If something has a lot of high, it's probably critical
	return quantityIncreasesRisk && upgradeRisk(ctx, overallRiskScore, highCount, size)
}

// isMalcontent determines whether the scanned file is the malcontent binary itself
// which causes false positives and is generally better to ignore entirely.
func isMalcontent(path string) bool {
	if strings.ToLower(filepath.Base(path)) == NAME || strings.ToLower(filepath.Base(path)) == "mal" {
		return true
	}
	return false
}

// Generate builds the report for the file at path from its scan results mrs
// and its contents fc. When c.Rules is the rule set that produced mrs, matches
// are processed in the rules' declaration order, so the report does not depend
// on which scanner produced mrs, and per-rule work is cached across calls.
// With a nil c.Rules, matches are processed in the order mrs lists them and
// nothing is cached. highestRisk is HighestMatchRisk's result and is only read
// for scans (c.Scan). Generate only reads mrs, so goroutines may share it, and
// the report does not refer to fc once Generate returns.
func Generate(ctx context.Context, path string, mrs *yarax.ScanResults, c malcontent.Config, expath string, _ *clog.Logger, fc []byte, size int64, checksum string, kind *programkind.FileType, highestRisk int) (*malcontent.FileReport, error) {
	if ctx.Err() != nil {
		return &malcontent.FileReport{}, ctx.Err()
	}

	if mrs == nil {
		return nil, fmt.Errorf("scan failed")
	}
	return buildReport(ctx, path, mrs.MatchingRules(), c, expath, fc, size, checksum, kind, highestRisk)
}

// GenerateRules is Generate for the rules that scans of the file at path
// matched, which may come from several rule sets, such as rule sets divided by
// scope, with any rule matched by more than one scan listed once. With c.Rules
// set, every listed rule needs a declaration index, from SetRuleOrder or from
// c.Rules itself. GenerateRules only reads the rules.
func GenerateRules(ctx context.Context, path string, matching []*yarax.Rule, c malcontent.Config, expath string, _ *clog.Logger, fc []byte, size int64, checksum string, kind *programkind.FileType, highestRisk int) (*malcontent.FileReport, error) {
	if ctx.Err() != nil {
		return &malcontent.FileReport{}, ctx.Err()
	}
	return buildReport(ctx, path, matching, c, expath, fc, size, checksum, kind, highestRisk)
}

func buildReport(ctx context.Context, path string, matching []*yarax.Rule, c malcontent.Config, expath string, fc []byte, size int64, checksum string, kind *programkind.FileType, highestRisk int) (*malcontent.FileReport, error) {
	displayPath := trimDisplayPath(path, expath, c)
	slashPath := filepath.ToSlash(displayPath)
	fileExt := ""
	if kind != nil {
		fileExt = kind.Ext
	}

	infos := ruleInfosFor(c.Rules)
	matches := make([]ruleMatch, len(matching))
	for i, m := range matching {
		matches[i] = ruleMatch{rule: m, info: infos.get(m)}
	}
	// A reused scanner reports matches in an order that depends on its earlier
	// scans, and the report depends on the order (ties, overrides, the
	// malcontent rule), so walk them in declaration order when it is known.
	// The copy keeps mrs untouched for other readers.
	if infos.ordered() {
		slices.SortStableFunc(matches, func(a, b ruleMatch) int {
			return cmp.Compare(a.info.order, b.info.order)
		})
	}

	ignore := buildIgnoreMap(c.IgnoreTags)
	rb := newReportBuilder(initFileReport(displayPath, checksum, size, len(matching)), fc, matching)

	ignoreMalcontent := false
	highCount := 0
	for _, rm := range matches {
		m, ri := rm.rule, rm.info
		if c.IgnoreSelf && m.Identifier() == NAME {
			ignoreMalcontent = true
		}

		if !ri.scope.matches(fileExt, slashPath) {
			continue
		}

		// Rule-level exclusion: filter *before* risk accumulation so an
		// excluded rule contributes nothing to the file's overall risk
		// score. Matching is on the rule identifier only.
		if ruleExcluded(m.Identifier(), c.IgnoreRules) {
			continue
		}

		if ri.risk == HIGH {
			highCount++
		}

		if skipMatch(ignoreMalcontent, ri.override, c.Scan, ri.risk, c.MinRisk, highestRisk) {
			continue
		}

		rb.add(m, ri, ignore)
	}

	fr := rb.finish(c.MinRisk, c.Scan)

	// Adjust the overall risk if we deviated from overallRiskScore
	// Scans will still need to drop <= medium results
	overallRiskScore := highestBehaviorRisk(fr)

	if applyCriticalUpgrade(ctx, c.QuantityIncreasesRisk, highCount, overallRiskScore, size) {
		overallRiskScore = CRITICAL
	}

	if skipScanFile(c.Scan, overallRiskScore) {
		fr.Skipped = "overall risk too low for scan"
	}

	// ignoreMalcontent is only set when c.IgnoreSelf is.
	if fr.IsMalcontent && ignoreMalcontent && isMalcontent(path) {
		fr.Skipped = "ignoring malcontent binary"
	}

	fr.RiskScore = overallRiskScore
	fr.RiskLevel = RiskLevels[fr.RiskScore]

	// Ensure that the behaviors are consistently sorted by ID
	slices.SortFunc(fr.Behaviors, func(a, b *malcontent.Behavior) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return fr, nil
}

// ruleMatch pairs a matching rule with its ruleInfo.
type ruleMatch struct {
	rule *yarax.Rule
	info *ruleInfo
}

// reportBuilder accumulates one file's report from the rules that matched it.
type reportBuilder struct {
	fr *malcontent.FileReport
	fc []byte
	// matching lists every rule that matched the file. matched indexes their
	// identifiers once an override rule needs to look one up.
	matching []*yarax.Rule
	matched  map[string]struct{}
	// behaviorIdx maps each behavior ID to its index in fr.Behaviors, and
	// sources holds the rule behind the behavior at each index.
	behaviorIdx map[string]int
	sources     []*yarax.Rule
	overrides   []overrideTarget
	pledges     []string
	caps        []string
	syscalls    []string
	// scratch collects one rule's matched strings at a time.
	scratch []string
}

func newReportBuilder(fr *malcontent.FileReport, fc []byte, matching []*yarax.Rule) reportBuilder {
	return reportBuilder{
		fr:          fr,
		fc:          fc,
		matching:    matching,
		behaviorIdx: make(map[string]int, len(matching)),
		sources:     make([]*yarax.Rule, 0, len(matching)),
		pledges:     []string{},
		caps:        []string{},
		syscalls:    []string{},
	}
}

// add records a match of rule m, described by ri, as a behavior unless the
// rule annotates the file instead or carries a tag in ignore.
func (rb *reportBuilder) add(m *yarax.Rule, ri *ruleInfo, ignore map[string]struct{}) {
	b, valid := rb.behavior(ri)
	if len(b.Override) > 0 {
		// Override entries copy b even when it is dropped below.
		b.MatchStrings = rb.render(m)
	}

	// if the rule has an override tag but is not overriding a valid rule,
	// ignore this match rule so that we don't show errant false positive rules in reports
	if !valid {
		return
	}

	// Fix YARA Forge rules that record their author URL as reference URLs.
	// An empty reference is a prefix of every URL, so it must not count.
	if b.ReferenceURL != "" && strings.HasPrefix(b.RuleURL, b.ReferenceURL) {
		b.RuleAuthorURL = b.ReferenceURL
		b.ReferenceURL = ""
	}

	// Meta names are weird and unfortunate, depending on whether they hold a value
	if ri.isMeta {
		rb.fr.Meta[ri.metaKey] = ri.metaValue
		return
	}

	if ignoreMatch(m.Tags(), ignore) {
		rb.fr.FilteredBehaviors++
		return
	}

	// If the rule does not have a description, make one up based on the rule name
	if b.Description == "" {
		b.Description = ri.fallbackDescription
	}

	if i := updateBehavior(rb.fr, b, b.ID, rb.behaviorIdx); i == len(rb.sources) {
		rb.sources = append(rb.sources, m)
	} else if i >= 0 {
		rb.sources[i] = m
	}
}

// behavior returns the behavior ri describes, with the effect of an override
// rule's directives on this file, and records the file attributes the rule
// declares. It reports false for an override rule that names a rule that did
// not match the file.
func (rb *reportBuilder) behavior(ri *ruleInfo) (*malcontent.Behavior, bool) {
	b := new(malcontent.Behavior)
	*b = ri.behavior

	valid := true
	for _, t := range ri.targets {
		if !rb.isMatching(t.rule) {
			valid = false
			continue
		}
		if ri.thirdParty {
			continue
		}
		b.RiskLevel = RiskLevels[t.score]
		b.RiskScore = t.score
		b.Override = append(b.Override, t.rule)
		rb.overrides = append(rb.overrides, overrideTarget{rule: b, target: t.rule, score: t.score})
	}

	if ri.isMalcontent {
		rb.fr.IsMalcontent = true
	}
	rb.pledges = append(rb.pledges, ri.pledges...)
	rb.caps = append(rb.caps, ri.caps...)
	rb.syscalls = append(rb.syscalls, ri.syscalls...)
	return b, valid
}

// isMatching reports whether a rule with identifier id matched the file.
func (rb *reportBuilder) isMatching(id string) bool {
	if rb.matched == nil {
		rb.matched = make(map[string]struct{}, len(rb.matching))
		for _, m := range rb.matching {
			rb.matched[m.Identifier()] = struct{}{}
		}
	}
	_, ok := rb.matched[id]
	return ok
}

// render returns the match strings for a behavior of rule m.
func (rb *reportBuilder) render(m *yarax.Rule) []string {
	rb.scratch = appendMatchedStrings(rb.scratch[:0], rb.fc, m)
	return matchStrings(m.Identifier(), rb.scratch)
}

// finish applies the recorded overrides and returns the report. Match strings
// are rendered only for the behaviors that remain, since rendering is the
// costliest step and scans drop most behaviors.
func (rb *reportBuilder) finish(minScore int, scan bool) *malcontent.FileReport {
	fr := rb.fr
	fr.Overrides = overrideEntries(rb.overrides)
	fr.Behaviors = handleOverrides(fr.Behaviors, fr.Overrides, minScore, scan)
	for _, b := range fr.Behaviors {
		// add rendered the strings of override rules already.
		if len(b.Override) == 0 {
			b.MatchStrings = rb.render(rb.sources[rb.behaviorIdx[b.ID]])
		}
	}

	slices.Sort(rb.pledges)
	slices.Sort(rb.syscalls)
	slices.Sort(rb.caps)
	fr.Pledge = slices.Compact(rb.pledges)
	fr.Syscalls = slices.Compact(rb.syscalls)
	fr.Capabilities = slices.Compact(rb.caps)
	return fr
}

func buildIgnoreMap(ignoreTags []string) map[string]struct{} {
	if len(ignoreTags) == 0 {
		return nil
	}
	ignore := make(map[string]struct{}, len(ignoreTags))
	for _, t := range ignoreTags {
		ignore[t] = struct{}{}
	}
	return ignore
}

func trimDisplayPath(path string, expath string, c malcontent.Config) string {
	displayPath := path
	if c.OCI {
		displayPath = strings.TrimPrefix(path, expath)
	}
	return TrimPrefixes(displayPath, c.TrimPrefixes)
}

func initFileReport(path string, checksum string, size int64, matchCount int) *malcontent.FileReport {
	return &malcontent.FileReport{
		Path:      path,
		SHA256:    checksum,
		Size:      size,
		Meta:      map[string]string{},
		Behaviors: make([]*malcontent.Behavior, 0, matchCount),
	}
}

// overrideTarget records one override directive: the override rule behind the
// behavior rule sets the rule named target to score.
type overrideTarget struct {
	rule   *malcontent.Behavior
	target string
	score  int
}

// overrideEntries expands override directives into one behavior per target, so
// each overridden rule receives the severity its own meta key declares rather
// than the last severity the override rule listed. Callers build the entries
// once every match is processed, so they carry the override rule's final
// description and URLs.
func overrideEntries(targets []overrideTarget) []*malcontent.Behavior {
	entries := make([]*malcontent.Behavior, 0, len(targets))
	for _, t := range targets {
		e := *t.rule
		e.Override = []string{t.target}
		e.RiskScore = t.score
		e.RiskLevel = RiskLevels[t.score]
		entries = append(entries, &e)
	}
	return entries
}

// updateBehavior dedupes by key against fr.Behaviors using idx, which maps
// each key to its index in fr.Behaviors, so insertion is O(1) amortized.
// When the same key has already been seen, the entry with the higher
// RiskScore wins (in-place replace at the existing slot); when the score
// is equal-or-greater than the current entry, the longer description
// wins. The slice itself is not sorted here; the caller is responsible
// for any finalize-time sort. It returns the index b now occupies in
// fr.Behaviors, or -1 when b was not stored.
func updateBehavior(fr *malcontent.FileReport, b *malcontent.Behavior, key string, idx map[string]int) int {
	i, ok := idx[key]
	if !ok {
		fr.Behaviors = append(fr.Behaviors, b)
		idx[key] = len(fr.Behaviors) - 1
		return len(fr.Behaviors) - 1
	}

	existing := fr.Behaviors[i]
	if existing.RiskScore < b.RiskScore {
		fr.Behaviors[i] = b
		return i
	}
	if len(existing.Description) < len(b.Description) && existing.RiskScore <= b.RiskScore {
		existing.Description = b.Description
	}
	return -1
}

// upgradeRisk determines whether to upgrade risk based on finding density,
// given the number of HIGH findings.
func upgradeRisk(ctx context.Context, riskScore int, highCount int, size int64) bool {
	if riskScore != HIGH {
		return false
	}

	upgrade := highCount > highLimit(size)
	if upgrade {
		clog.DebugContextf(ctx, "upgrading risk to critical: high=%d, size=%d", highCount, size)
	}
	return upgrade
}

// highLimit returns how many HIGH findings a file of size bytes may hold
// before upgradeRisk raises its risk to CRITICAL. Larger files may hold more.
func highLimit(size int64) int {
	if size < 1024 {
		// small scripts, tiny ELF binaries
		return 1
	}
	sizeMB := size / 1024 / 1024
	if sizeMB < 2 {
		// include most UPX binaries
		return 2
	}
	if sizeMB < 4 {
		return 3
	}
	if sizeMB < 10 {
		return 4
	}
	return 5
}

// HighestMatchRisk returns the highest risk score among the rules that actually
// apply to the scanned file. It mirrors Generate's scoping: rules excluded by a
// file's type or path globs are not counted, so the value used as the
// scan-mode skipMatch threshold cannot be inflated by a rule that Generate
// would drop. kind/path/expath/c match the arguments passed to Generate, and
// c.Rules enables the same per-rule caching.
func HighestMatchRisk(mrs *yarax.ScanResults, kind *programkind.FileType, path string, expath string, c malcontent.Config) int {
	if mrs == nil {
		return 0
	}
	return HighestMatchRiskRules(mrs.MatchingRules(), kind, path, expath, c)
}

// HighestMatchRiskRules is HighestMatchRisk for the rules that scans of the
// file matched, as GenerateRules receives them.
func HighestMatchRiskRules(matching []*yarax.Rule, kind *programkind.FileType, path string, expath string, c malcontent.Config) int {
	slashPath := filepath.ToSlash(trimDisplayPath(path, expath, c))
	ext := ""
	if kind != nil {
		ext = kind.Ext
	}

	infos := ruleInfosFor(c.Rules)
	var highestRisk int
	for _, m := range matching {
		if ri := infos.get(m); ri.scope.matches(ext, slashPath) {
			highestRisk = max(highestRisk, ri.risk)
		}
	}
	return highestRisk
}

// highestBehaviorRisk returns the highest risk score from a slice of FileReport Behaviors.
func highestBehaviorRisk(fr *malcontent.FileReport) int {
	if fr == nil {
		return 0
	}

	var highestRisk int
	for _, b := range fr.Behaviors {
		highestRisk = max(highestRisk, b.RiskScore)
	}

	return highestRisk
}

// handleOverrides modifies the behavior slice based on the contents of the override slice.
// When several entries target the same rule, the later entry wins.
func handleOverrides(original, override []*malcontent.Behavior, minScore int, scan bool) []*malcontent.Behavior {
	behaviorMap := make(map[string]*malcontent.Behavior, len(original))
	for _, b := range original {
		behaviorMap[b.RuleName] = b
	}

	for _, o := range override {
		for _, ob := range o.Override {
			if b, exists := behaviorMap[ob]; exists {
				b.RiskLevel = o.RiskLevel
				b.RiskScore = o.RiskScore
			}
		}
		// Delete the override rule from the behavior map
		delete(behaviorMap, o.RuleName)
	}

	// Scans report only HIGH and above, the same floor Generate applies to the
	// file risk. QuantityIncreasesRisk decides only whether many HIGH findings
	// raise the file to CRITICAL, so it does not change which behaviors stay.
	threshold := minScore
	if scan {
		threshold = HIGH
	}

	modified := make([]*malcontent.Behavior, 0, len(behaviorMap))
	for _, b := range behaviorMap {
		if b.RiskScore >= threshold {
			modified = append(modified, b)
		}
	}

	return modified
}
