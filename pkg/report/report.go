// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"

	yarax "github.com/VirusTotal/yara-x/go"
)

const NAME string = "malcontent"

const (
	HARMLESS int = iota
	LOW
	MEDIUM
	HIGH
	CRITICAL
)

// Map to handle RiskScore -> RiskLevel conversions.
var RiskLevels = map[int]string{
	0: "NONE",     // harmless: common to all executables, no system impact
	1: "LOW",      // undefined: low impact, common to good and bad executables
	2: "MEDIUM",   // notable: may have impact, but common
	3: "HIGH",     // suspicious: uncommon, but could be legit
	4: "CRITICAL", // critical: certainly malware
}

// yaraForge has some very, very long rule names.
var yaraForgeJunkWords = map[string]bool{
	"0":                 true,
	"1":                 true,
	"2":                 true,
	"apt":               true,
	"artefacts":         true,
	"artifacts":         true,
	"base":              true,
	"big":               true,
	"controller":        true,
	"dynamic":           true,
	"encoded":           true,
	"exe":               true,
	"forensic":          true,
	"forensicartifacts": true,
	"generic":           true,
	"greyware":          true,
	"hunting":           true,
	"indicator":         true,
	"keyword":           true,
	"linux":             true,
	"lnx":               true,
	"m":                 true,
	"mac":               true,
	"macos":             true,
	"mal":               true,
	"malware":           true,
	"offensive":         true,
	"osx":               true,
	"small":             true,
	"suspicious":        true,
	"tool":              true,
	"trojan":            true,
	"unix":              true,
	"YARAForge":         true,
}

// authorWithURLRe matches "Arnim Rupp (https://github.com/ruppde)"
var (
	authorWithURLRe        = regexp.MustCompile(`(.*?) \((http.*)\)`)
	threatHuntingKeywordRe = regexp.MustCompile(`Detection patterns for the tool '(.*)' taken from the ThreatHunting-Keywords github project`)
	dateRe                 = regexp.MustCompile(`[a-z]{3}\d{1,2}`)
)

// Map to handle RiskLevel -> RiskScore conversions.
var Levels = map[string]int{
	"ignore":     -1,
	"none":       -1,
	"harmless":   0,
	"low":        1,
	"notable":    2,
	"medium":     2,
	"suspicious": 3,
	"weird":      3,
	"high":       3,
	"crit":       4,
	"critical":   4,
}

func thirdPartyKey(path string, rule string) string {
	// include the directory
	yaraIndex := strings.Index(path, "yara/")
	if yaraIndex == -1 {
		return ""
	}
	subDir := path[yaraIndex+5 : strings.IndexByte(path[yaraIndex+5:], '/')+yaraIndex+5]
	words := []string{subDir}

	// ELASTIC_Linux_Trojan_Gafgyt_E4A1982B
	words = append(words, strings.Split(strings.ToLower(rule), "_")...)

	// strip off the last word if it's a hex key
	lastWord := words[len(words)-1]
	_, err := strconv.ParseUint(lastWord, 16, 64)
	if err == nil {
		words = words[0 : len(words)-1]
	}

	var keepWords []string
	for x, w := range words {
		// ends with a date
		if x == len(words)-1 && dateRe.MatchString(w) {
			continue
		}
		if w == "" {
			continue
		}

		if !yaraForgeJunkWords[w] {
			keepWords = append(keepWords, w)
		}
	}
	if len(keepWords) > 4 {
		keepWords = keepWords[0:4]
	}

	src := keepWords[0]

	// Fix name for https://github.com/Neo23x0/signature-base within YARAForge
	if src == "signature" {
		src = "sig_base"
	}
	rulename := keepWords[1:]

	key := fmt.Sprintf("3P/%s/%s", src, strings.Join(rulename, "_"))
	return key
}

// thirdParty returns whether the rule is sourced from a 3rd party.
func thirdParty(src string) bool {
	return strings.Contains(src, "yara/")
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
	key = strings.ReplaceAll(key, ".yara", "")

	// Reduce stutter: if the rule is prefixed with the directory name, remove the prefix

	dirParts := strings.Split(key, "/")
	// ID's generally follow: `<namespace>/<resource>/<technique>`
	ns := dirParts[0]
	// namespaces can have dashes, like 'anti-static'
	ns = strings.ReplaceAll(ns, "_", "-")
	rsrc := dirParts[len(dirParts)-2]
	tech := dirParts[len(dirParts)-1]

	tech = strings.ReplaceAll(tech, rsrc, "")
	tech = strings.ReplaceAll(tech, "__", "_")
	tech = strings.Trim(tech, "_")

	dirParts[0] = ns
	dirParts[len(dirParts)-1] = tech
	return strings.TrimSuffix(strings.Join(dirParts, "/"), "/")
}

func generateRuleURL(src string, rule string) string {
	// Linking to exact commit and line number would be ideal, but
	// we aren't parsing that information out of our YARA files yet
	return fmt.Sprintf("https://github.com/chainguard-dev/malcontent/blob/main/rules/%s#%s", src, rule)
}

func ignoreMatch(tags []string, ignoreTags map[string]bool) bool {
	for _, t := range tags {
		if ignoreTags[t] {
			return true
		}
	}
	return false
}

func behaviorRisk(ns string, rule string, tags []string) int {
	risk := 1

	if thirdParty(ns) {
		risk = 3
		src := strings.Split(ns, "/")[1]

		switch src {
		case "JPCERT", "YARAForge", "bartblaze", "huntress", "elastic":
			risk = 4
			if strings.Contains(strings.ToLower(ns), "generic") ||
				strings.Contains(strings.ToLower(rule), "generic") {
				risk = 3
			}
		}

		if strings.Contains(strings.ToLower(ns), "keyword") ||
			strings.Contains(strings.ToLower(rule), "keyword") {
			risk = 2
		}
	}

	if strings.Contains(ns, "combo/") {
		risk = 2
	}

	for _, tag := range tags {
		if r, ok := Levels[tag]; ok {
			return r
		}
	}

	return risk
}

func longestUnique(raw []string) []string {
	if len(raw) <= 1 {
		return raw
	}

	safe := make([]string, len(raw))
	copy(safe, raw)

	// Sort by length first (descending)
	sort.Slice(safe, func(i, j int) bool {
		return len(safe[i]) > len(safe[j])
	})

	longest := make([]string, 0, len(safe))
	seen := make(map[string]bool, len(safe))

	// Since we sorted by length, longest strings come first
	// This ensures we keep the longest strings that contain shorter ones
	for _, s := range safe {
		if s == "" || seen[s] {
			continue
		}

		isLongest := true
		for _, o := range longest {
			if strings.Contains(o, s) {
				isLongest = false
				break
			}
		}
		if isLongest {
			longest = append(longest, s)
			seen[s] = true
		}
	}

	return longest
}

func matchToString(ruleName string, m string) string {
	if containsUnprintable([]byte(m)) {
		return ruleName
	}

	switch {
	case strings.Contains(ruleName, "base64"),
		strings.Contains(ruleName, "xor"):
		return ruleName + "::" + m
	case strings.Contains(ruleName, "xml_key_val"):
		return strings.TrimSpace(strings.ReplaceAll(
			strings.ReplaceAll(m, "<key>", ""),
			"</key>", "",
		))
	}
	return strings.TrimSpace(m)
}

// extract match strings.
func matchStrings(ruleName string, ms []string) []string {
	if len(ms) == 0 {
		return nil
	}

	// Create a thread-safe copy of the input
	safe := make([]string, len(ms))
	copy(safe, ms)

	raw := make([]string, 0, len(safe))

	// Process strings while keeping thread safety
	for _, m := range safe {
		str := matchToString(ruleName, m)
		if str != "" {
			raw = append(raw, str)
		}
	}

	return longestUnique(raw)
}

// sizeAndChecksum calculates size and checksum using already-read file contents if available.
func sizeAndChecksum(fc []byte) (int64, string) {
	var checksum string
	var size int64

	if len(fc) > 0 {
		size = int64(len(fc))
		h := sha256.New()
		h.Write(fc)
		checksum = fmt.Sprintf("%x", h.Sum(nil))
	}

	return size, checksum
}

// fixURL fixes badly formed URLs.
func fixURL(s string) string {
	// YARAforge forgets to encode spaces, but encodes everything else
	return strings.ReplaceAll(s, " ", "%20")
}

// mungeDescription shortens verbose descriptions.
func mungeDescription(s string) string {
	// in: Detection patterns for the tool 'Nsight RMM' taken from the ThreatHunting-Keywords github project
	// out: references 'Nsight RMM'
	m := threatHuntingKeywordRe.FindStringSubmatch(s)
	if len(m) > 0 {
		return fmt.Sprintf("references '%s' tool", m[1])
	}
	return s
}

// TrimPrefixes removes the specified prefix from a given path for the purposes of sample test data generation.
// This function will only be used via the refresh package.
func TrimPrefixes(path string, prefixes []string) string {
	for _, prefix := range prefixes {
		if prefix == "" {
			continue
		}
		prefix = strings.TrimPrefix(prefix, "./")
		if strings.HasPrefix(path, prefix) {
			trimmed := path[len(prefix):]
			return strings.TrimPrefix(trimmed, string(filepath.Separator))
		}
	}
	return path
}

// fileMatchesRules checks the scanned file's type against a rule's defined filetypes.
func fileMatchesRule(meta []yarax.Metadata, ext string) bool {
	for _, m := range meta {
		if m.Identifier() == "filetypes" {
			filetypes := strings.Split(fmt.Sprintf("%s", m.Value()), ",")
			return slices.Contains(filetypes, ext)
		}
	}
	// Rules without filetype metadata are universal
	return true
}

//nolint:cyclop // ignore complexity of 64
func Generate(ctx context.Context, path string, mrs *yarax.ScanResults, c malcontent.Config, expath string, _ *clog.Logger, fc []byte, kind *programkind.FileType) (*malcontent.FileReport, error) {
	if ctx.Err() != nil {
		return &malcontent.FileReport{}, ctx.Err()
	}

	if mrs == nil {
		return nil, fmt.Errorf("scan failed")
	}

	ignoreTags := c.IgnoreTags
	minScore := c.MinRisk
	ignoreSelf := c.IgnoreSelf

	ignore := buildIgnoreMap(ignoreTags)
	size, checksum := sizeAndChecksum(fc)

	displayPath := trimDisplayPath(path, expath, c)

	matchCount := len(mrs.MatchingRules())
	fr := initFileReport(displayPath, checksum, size, matchCount)

	pledges := make([]string, 0, 4)
	caps := make([]string, 0, 4)
	syscalls := make([]string, 0, 8)

	ignoreMalcontent := false
	key := ""
	overallRiskScore := 0
	risk := 0
	riskCounts := make(map[int]int, 0)

	highestRisk := HighestMatchRisk(mrs)
	// Store match rules in a map for future override operations
	mrsMap := createMatchRulesMap(mrs, matchCount)

	for _, m := range mrs.MatchingRules() {
		if all(m.Identifier() == NAME, ignoreSelf) {
			ignoreMalcontent = true
		}

		if kind != nil && kind.Ext != "" {
			if !fileMatchesRule(m.Metadata(), kind.Ext) {
				continue
			}
		}

		override := slices.Contains(m.Tags(), "override")

		risk = behaviorRisk(m.Namespace(), m.Identifier(), m.Tags())
		overallRiskScore = max(overallRiskScore, risk)
		riskCounts[risk]++
		// The malcontent rule is classified as harmless
		// A !ignoreMalcontent condition will prevent the rule from being filtered
		// If running a scan as opposed to an analyze,
		// drop any matches that fall below the highest risk
		switch {
		case risk == -1:
			continue
		case risk < minScore && !ignoreMalcontent && !override:
			continue
		case c.Scan && risk < highestRisk && !ignoreMalcontent && !override:
			continue
		}

		key = generateKey(m.Namespace(), m.Identifier())
		ruleURL := generateRuleURL(m.Namespace(), m.Identifier())

		matchedStrings := processMatchedStrings(fc, m)

		b := buildBehavior(m, matchedStrings, key, ruleURL, risk)

		handleMetadata(m, b, fr, override, mrsMap, pledges, caps, syscalls)

		// Fix YARA Forge rules that record their author URL as reference URLs
		if strings.HasPrefix(b.RuleURL, b.ReferenceURL) {
			b.RuleAuthorURL = b.ReferenceURL
			b.ReferenceURL = ""
		}

		// Meta names are weird and unfortunate, depending on whether they hold a value
		if strings.HasPrefix(key, "meta/") {
			k := strings.ReplaceAll(filepath.Dir(key), "meta/", "")
			v := filepath.Base(key)

			fr.Meta[k] = v
			continue
		}

		if ignoreMatch(m.Tags(), ignore) {
			fr.FilteredBehaviors++
			continue
		}

		// If the rule does not have a description, make one up based on the rule name
		if b.Description == "" {
			b.Description = strings.ReplaceAll(m.Identifier(), "_", " ")
		}

		updateBehavior(fr, b, key)

		// TODO: If we match multiple rules within a single namespace, merge matchstrings
	}

	// Update the behaviors to account for overrides
	fr.Behaviors = handleOverrides(fr.Behaviors, fr.Overrides, minScore)

	// Adjust the overall risk if we deviated from overallRiskScore
	// Scans will still need to drop <= medium results
	newRisk := highestBehaviorRisk(fr)
	if overallRiskScore != newRisk {
		overallRiskScore = newRisk
	}

	if c.Scan && overallRiskScore < HIGH {
		fr.Skipped = "overall risk too low for scan"
	}

	// Check for both the full and shortened variants of malcontent
	isMalBinary := (filepath.Base(path) == NAME || filepath.Base(path) == "mal")

	if all(ignoreSelf, fr.IsMalcontent, ignoreMalcontent, isMalBinary) {
		fr.Skipped = "ignoring malcontent binary"
	}

	// If something has a lot of high, it's probably critical
	if c.QuantityIncreasesRisk && upgradeRisk(ctx, overallRiskScore, riskCounts, size) {
		overallRiskScore = 4
	}

	slices.Sort(pledges)
	slices.Sort(syscalls)
	slices.Sort(caps)
	fr.Pledge = slices.Compact(pledges)
	fr.Syscalls = slices.Compact(syscalls)
	fr.Capabilities = slices.Compact(caps)
	fr.RiskScore = overallRiskScore
	fr.RiskLevel = RiskLevels[fr.RiskScore]

	// Ensure that the behaviors are consistently sorted by ID
	sort.Slice(fr.Behaviors, func(i, j int) bool {
		return fr.Behaviors[i].ID < fr.Behaviors[j].ID
	})

	return fr, nil
}

func buildIgnoreMap(ignoreTags []string) map[string]bool {
	ignore := make(map[string]bool, len(ignoreTags))
	for _, t := range ignoreTags {
		ignore[t] = true
	}
	return ignore
}

func trimDisplayPath(path string, expath string, c malcontent.Config) string {
	displayPath := path
	if c.OCI {
		displayPath = strings.TrimPrefix(path, expath)
	}
	if len(c.TrimPrefixes) > 0 {
		displayPath = TrimPrefixes(displayPath, c.TrimPrefixes)
	}
	return displayPath
}

func initFileReport(path string, checksum string, size int64, matchCount int) *malcontent.FileReport {
	return &malcontent.FileReport{
		Path:      path,
		SHA256:    checksum,
		Size:      size,
		Meta:      make(map[string]string, matchCount),
		Behaviors: make([]*malcontent.Behavior, 0, matchCount),
		Overrides: make([]*malcontent.Behavior, 0, matchCount/10),
	}
}

func createMatchRulesMap(mrs *yarax.ScanResults, matchCount int) map[string]*yarax.Rule {
	mrsMap := make(map[string]*yarax.Rule, matchCount)
	for _, m := range mrs.MatchingRules() {
		mrsMap[m.Identifier()] = m
	}
	return mrsMap
}

func processMatchedStrings(fc []byte, m *yarax.Rule) []string {
	totalMatches := 0
	for _, p := range m.Patterns() {
		totalMatches += len(p.Matches())
	}

	matches := make([]yarax.Match, 0, totalMatches)
	for _, p := range m.Patterns() {
		matches = append(matches, p.Matches()...)
	}

	processor := newMatchProcessor(fc, matches, m.Patterns())
	return processor.process()
}

func buildBehavior(m *yarax.Rule, matchedStrings []string, key string, ruleURL string, risk int) *malcontent.Behavior {
	return &malcontent.Behavior{
		ID:           key,
		MatchStrings: matchStrings(m.Identifier(), matchedStrings),
		RiskLevel:    RiskLevels[risk],
		RiskScore:    risk,
		RuleName:     m.Identifier(),
		RuleURL:      ruleURL,
	}
}

func handleMetadata(m *yarax.Rule, b *malcontent.Behavior, fr *malcontent.FileReport, override bool, mrsMap map[string]*yarax.Rule, pledges []string, caps []string, syscalls []string) {
	k := ""
	v := ""

	for _, meta := range m.Metadata() {
		k = meta.Identifier()
		v = fmt.Sprintf("%s", meta.Value())
		// Empty data is unusual, so just ignore it.
		if k == "" || v == "" {
			continue
		}

		// If we find a match in the map for the metadata key, that's the rule to override
		// Store this rule (the override) in the fr.Overrides behavior slice
		// If an override rule is not overriding a valid rule, log an error
		_, exists := mrsMap[k]
		switch {
		case exists && override:
			var overrideSev int
			if sev, ok := Levels[v]; ok {
				overrideSev = sev
			}
			b.RiskLevel = RiskLevels[overrideSev]
			b.RiskScore = overrideSev
			b.Override = append(b.Override, k)
			fr.Overrides = append(fr.Overrides, b)
		case !exists && override:
			// TODO: return error if override references an unknown rule name
			continue
		}

		switch k {
		case "author":
			b.RuleAuthor = v
			m := authorWithURLRe.FindStringSubmatch(v)
			if len(m) > 0 && isValidURL(m[2]) {
				b.RuleAuthor = m[1]
				b.RuleAuthorURL = m[2]
			}
			// If author is in @username format, strip @ to avoid constantly pinging them on GitHub
			if strings.HasPrefix(b.RuleAuthor, "@") {
				b.RuleAuthor = strings.Replace(b.RuleAuthor, "@", "", 1)
			}
		case "author_url":
			b.RuleAuthorURL = v
		case fmt.Sprintf("__%s__", NAME):
			if v == "true" {
				fr.IsMalcontent = true
			}
		case "license":
			b.RuleLicense = v
		case "license_url":
			b.RuleLicenseURL = v
		case "description", "threat_name", "name":
			desc := mungeDescription(v)
			if len(desc) > len(b.Description) {
				b.Description = desc
			}
		case "ref", "reference":
			u := fixURL(v)
			if isValidURL(u) {
				b.ReferenceURL = u
			}
		case "source_url":
			// YARAforge forgets to encode spaces
			b.RuleURL = fixURL(v)
		case "pledge":
			pledges = append(pledges, v)
		case "syscall":
			sy := strings.Split(v, ",")
			syscalls = append(syscalls, sy...)
		case "cap":
			caps = append(caps, v)
		}
	}
}

func updateBehavior(fr *malcontent.FileReport, b *malcontent.Behavior, key string) {
	existingIndex := -1
	for i, existing := range fr.Behaviors {
		if existing.ID == key {
			existingIndex = i
			break
		}
	}

	// If the existing description is longer and the priority is the same or lower
	if existingIndex != -1 {
		if fr.Behaviors[existingIndex].RiskScore < b.RiskScore {
			fr.Behaviors = append(fr.Behaviors[:existingIndex], append([]*malcontent.Behavior{b}, fr.Behaviors[existingIndex+1:]...)...)
		}
		if len(fr.Behaviors[existingIndex].Description) < len(b.Description) && fr.Behaviors[existingIndex].RiskScore <= b.RiskScore {
			fr.Behaviors[existingIndex].Description = b.Description
		}
	} else {
		fr.Behaviors = append(fr.Behaviors, b)
	}
}

// upgradeRisk determines whether to upgrade risk based on finding density.
func upgradeRisk(ctx context.Context, riskScore int, riskCounts map[int]int, size int64) bool {
	if riskScore != 3 {
		return false
	}
	highCount := riskCounts[3]
	sizeMB := size / 1024 / 1024
	upgrade := false

	switch {
	// small scripts, tiny ELF binaries
	case size < 1024 && highCount > 1:
		upgrade = true
	// include most UPX binaries
	case sizeMB < 2 && highCount > 2:
		upgrade = true
	case sizeMB < 4 && highCount > 3:
		upgrade = true
	case sizeMB < 10 && highCount > 4:
		upgrade = true
	case sizeMB < 20 && highCount > 5:
		upgrade = true
	case highCount > 6:
		upgrade = true
	case !upgrade:
		upgrade = false
	}

	clog.DebugContextf(ctx, "upgrading risk: high=%d, size=%d", highCount, size)
	return upgrade
}

// all returns a single boolean based on a slice of booleans.
func all(conditions ...bool) bool {
	for _, condition := range conditions {
		if !condition {
			return false
		}
	}
	return true
}

// HighestMatchRisk returns the highest risk score from a slice of MatchRules.
func HighestMatchRisk(mrs *yarax.ScanResults) int {
	if len(mrs.MatchingRules()) == 0 {
		return 0
	}

	var highestRisk int
	for _, m := range mrs.MatchingRules() {
		risk := behaviorRisk(m.Namespace(), m.Identifier(), m.Tags())
		highestRisk = max(highestRisk, risk)
	}
	return highestRisk
}

// highestBehaviorRisk returns the highest risk score from a slice of FileReport Behaviors.
func highestBehaviorRisk(fr *malcontent.FileReport) int {
	if fr == nil || len(fr.Behaviors) == 0 {
		return 0
	}

	var highestRisk int
	for _, b := range fr.Behaviors {
		highestRisk = max(highestRisk, b.RiskScore)
	}

	return highestRisk
}

// handleOverrides modifies the behavior slice based on the contents of the override slice.
func handleOverrides(original, override []*malcontent.Behavior, minScore int) []*malcontent.Behavior {
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

	modified := make([]*malcontent.Behavior, 0, len(behaviorMap))
	for _, b := range behaviorMap {
		if b.RiskScore >= minScore {
			modified = append(modified, b)
		}
	}

	return modified
}
