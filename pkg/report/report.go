// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/clog"
	"github.com/hillu/go-yara/v4"
)

var RiskLevels = map[int]string{
	0: "NONE",     // harmless: common to all executables, no system impact
	1: "LOW",      // undefined: low impact, common to good and bad executables
	2: "MEDIUM",   // notable: may have impact, but common
	3: "HIGH",     // suspicious: uncommon, but could be legit
	4: "CRITICAL", // critical: certainly malware
}

// yaraForge has some very very long rule names.
var yaraForgeJunkWords = map[string]bool{
	"controller":        true,
	"generic":           true,
	"apt":               true,
	"malware":           true,
	"mal":               true,
	"trojan":            true,
	"m":                 true,
	"hunting":           true,
	"dynamic":           true,
	"big":               true,
	"small":             true,
	"encoded":           true,
	"forensicartifacts": true,
	"lnx":               true,
	"linux":             true,
	"macos":             true,
	"osx":               true,
	"mac":               true,
	"indicator":         true,
	"suspicious":        true,
}

// dropRules are noisy 3rd party rules to silently ignore.
var dropRules = map[string]bool{
	"3P/godmoderules/iddqd/god/mode": true,
}

var dateRe = regexp.MustCompile(`[a-z]{3}\d{1,2}`)

func yaraForgeKey(rule string) string {
	// ELASTIC_Linux_Trojan_Gafgyt_E4A1982B
	words := strings.Split(strings.ToLower(rule), "_")

	// strip off the last wold if it's a hex key
	lastWord := words[len(words)-1]
	_, err := strconv.ParseUint(lastWord, 16, 64)
	if err == nil {
		words = words[0 : len(words)-1]
	}
	keepWords := []string{}
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
	key := fmt.Sprintf("3P/%s", strings.Join(keepWords, "/"))
	return strings.ReplaceAll(key, "signature/base", "signature_base")
}

// yaraForge returns whether the rule is sourced from YARAForge.
func yaraForge(src string) bool {
	return strings.Contains(src, "yara-rules")
}

func generateKey(src string, rule string) string {
	if yaraForge(src) {
		return yaraForgeKey(rule)
	}

	_, after, _ := strings.Cut(src, "third_party/")
	if after != "" {
		key := strings.ReplaceAll(after, "-", "/")
		key = strings.ReplaceAll(key, "/rules", "")
		key = strings.ReplaceAll(key, "/yara", "")
		return "third_party/" + strings.ReplaceAll(key, ".yar", "")
	}

	key := strings.ReplaceAll(src, "-", "/")
	return strings.ReplaceAll(key, ".yara", "")
}

func generateRuleURL(src string, rule string) string {
	// TODO: get the exact lines to highlight
	return fmt.Sprintf("https://github.com/chainguard-dev/bincapz/blob/main/rules/%s#%s", src, rule)
}

func ignoreMatch(tags []string, ignoreTags map[string]bool) bool {
	for _, t := range tags {
		if ignoreTags[t] {
			return true
		}
	}
	return false
}

func behaviorRisk(ns string, tags []string) int {
	risk := 1

	levels := map[string]int{
		"harmless":   0,
		"notable":    2,
		"medium":     2,
		"suspicious": 3,
		"weird":      3,
		"high":       3,
		"crit":       4,
		"critical":   4,
	}

	if strings.Contains(ns, "combo/") {
		risk = 2
	}

	for _, tag := range tags {
		if r, ok := levels[tag]; ok {
			risk = r
		}
	}

	if strings.Contains(ns, "third_party/") {
		risk = 4
	}

	return risk
}

func unprintableString(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

func longestUnique(raw []string) []string {
	longest := []string{}

	// inefficiently remove substring matches
	for _, s := range slices.Compact(raw) {
		if s == "" {
			continue
		}

		isLongest := true
		for _, o := range raw {
			if o != s && strings.Contains(o, s) {
				isLongest = false
				break
			}
		}
		if isLongest {
			longest = append(longest, s)
		}
	}
	return longest
}

// convert MatchString to a usable string.
func matchToString(ruleName string, m yara.MatchString) string {
	s := string(m.Data)
	if strings.Contains(ruleName, "base64") && !strings.Contains(s, "base64") {
		s = fmt.Sprintf("%s::%s", s, m.Name)
	}
	if strings.Contains(ruleName, "xor") && !strings.Contains(s, "xor") {
		s = fmt.Sprintf("%s::%s", s, m.Name)
	}

	if unprintableString(s) {
		s = m.Name
	}

	// bad hack, can we do this in YARA?
	if strings.Contains(m.Name, "xml_key_val") {
		s = strings.ReplaceAll(s, "<key>", "")
		s = strings.ReplaceAll(s, "</key>", "")
	}
	return strings.TrimSpace(s)
}

// extract important values.
func matchValues(key string, ruleName string, ms []yara.MatchString) []string {
	raw := []string{}

	keyHasCombo := strings.Contains(key, "combo/")
	keyHasRef := strings.Contains(key, "ref/")
	keyHasXor := strings.Contains(key, "xor/")
	keyHasBase64 := strings.Contains(key, "base64/")
	ruleHasValue := strings.Contains(ruleName, "value")
	ruleHasVal := strings.HasSuffix(ruleName, "val")

	for _, m := range ms {
		keep := false

		switch {
		case strings.HasSuffix(m.Name, "val"):
			keep = true
		case keyHasCombo:
			keep = true
		case keyHasRef:
			keep = true
		case keyHasXor:
			keep = true
		case keyHasBase64:
			keep = true
		case ruleHasValue:
			keep = true
		case ruleHasVal:
			keep = true
		}
		if !keep {
			continue
		}

		raw = append(raw, matchToString(ruleName, m))
	}

	slices.Sort(raw)
	return longestUnique(raw)
}

// extract match strings.
func matchStrings(ruleName string, ms []yara.MatchString) []string {
	raw := []string{}

	for _, m := range ms {
		raw = append(raw, matchToString(ruleName, m))
	}

	slices.Sort(raw)
	return longestUnique(raw)
}

func pathChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("err-%v", err), nil
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func Generate(ctx context.Context, path string, mrs yara.MatchRules, ignoreTags []string, minScore int) (bincapz.FileReport, error) {
	ignore := map[string]bool{}
	for _, t := range ignoreTags {
		ignore[t] = true
	}

	ptCheck, err := pathChecksum(path)
	if err != nil {
		return bincapz.FileReport{}, err
	}

	fr := bincapz.FileReport{
		Path:      path,
		SHA256:    ptCheck,
		Meta:      map[string]string{},
		Behaviors: map[string]bincapz.Behavior{},
	}

	pledges := []string{}
	caps := []string{}
	syscalls := []string{}
	overallRiskScore := 0
	riskCounts := map[int]int{}
	packageRisks := []string{}

	for _, m := range mrs {
		risk := behaviorRisk(m.Namespace, m.Tags)
		if risk > overallRiskScore {
			overallRiskScore = risk
		}
		riskCounts[risk]++
		if risk < minScore {
			continue
		}
		key := generateKey(m.Namespace, m.Rule)
		if dropRules[key] {
			continue
		}

		ruleURL := generateRuleURL(m.Namespace, m.Rule)
		packageRisks = append(packageRisks, key)

		b := bincapz.Behavior{
			RiskScore:    risk,
			RiskLevel:    RiskLevels[risk],
			Values:       matchValues(key, m.Rule, m.Strings),
			MatchStrings: matchStrings(m.Rule, m.Strings),
			RuleURL:      ruleURL,
		}

		// process YARA meta key/value pairs
		for _, meta := range m.Metas {
			k := meta.Identifier
			v := fmt.Sprintf("%s", meta.Value)

			switch k {
			case "source_url":
				b.RuleURL = v
			case "author":
				b.RuleAuthor = v
			case "author_url":
				b.RuleAuthorURL = v
			case "reference", "ref":
				if yaraForge(m.Namespace) {
					b.RuleAuthorURL = v
					continue
				}
				b.ReferenceURL = v
			case "license", "license_url":
				b.RuleLicense = v
			case "description", "threat_name", "name":
				if len(v) > len(b.Description) {
					b.Description = v
				}
			case "pledge":
				pledges = append(pledges, v)
			case "syscall":
				sy := strings.Split(v, ",")
				syscalls = append(syscalls, sy...)
			case "cap":
				caps = append(caps, v)
			}
		}

		// This weird-looking heuristic fixes YARA Forge rules that were imported without a reference; for example, Elastic
		if !strings.HasPrefix(b.RuleURL, b.RuleAuthorURL) {
			b.ReferenceURL = b.RuleAuthorURL
			b.RuleAuthorURL = ""
		}

		// Meta names are weird and unfortunate, depending if they hold a value
		if strings.HasPrefix(key, "meta/") {
			k := strings.ReplaceAll(filepath.Dir(key), "meta/", "")
			v := filepath.Base(key)
			if len(b.Values) > 0 {
				k = strings.ReplaceAll(key, "meta/", "")
				v = strings.Join(b.Values, "\n")
			}

			fr.Meta[k] = v
			continue
		}

		if ignoreMatch(m.Tags, ignore) {
			fr.FilteredBehaviors++
			clog.DebugContextf(ctx, "dropping %s (tags match ignore list)", m.Namespace)
			continue
		}

		// We forgot :(
		if b.Description == "" {
			b.Description = strings.ReplaceAll(m.Rule, "_", " ")
		}

		// We've already seen a similar behavior: do we augment it or replace it?
		existing, exists := fr.Behaviors[key]
		if !exists || existing.RiskScore < b.RiskScore {
			fr.Behaviors[key] = b
			continue
		}

		if len(existing.Description) < len(b.Description) {
			existing.Description = b.Description
			fr.Behaviors[key] = existing
		}
	}
	// If something has a lot of high, it's probably critical
	if riskCounts[3] >= 4 {
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
	fr.PackageRisk = packageRisks

	return fr, nil
}
