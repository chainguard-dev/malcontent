// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"
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
	"YARAForge":         true,
	"exe":               true,
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
	"tool":              true,
	"keyword":           true,
	"indicator":         true,
	"suspicious":        true,
	"offensive":         true,
	"greyware":          true,
}

// thirdPartyCriticalSources are 3P sources that default to critical.
var thirdPartyCriticalSources = map[string]bool{
	"YARAForge": true,
	"huntress":  true,
	"bartblaze": true,
}

// authorWithURLRe matcehs "Arnim Rupp (https://github.com/ruppde)"
var authorWithURLRe = regexp.MustCompile(`(.*?) \((http.*)\)`)

var threatHuntingKeywordRe = regexp.MustCompile(`Detection patterns for the tool '(.*)' taken from the ThreatHunting-Keywords github project`)

var dateRe = regexp.MustCompile(`[a-z]{3}\d{1,2}`)

func thirdPartyKey(path string, rule string) string {
	// include the directory
	pathParts := strings.Split(path, "/")
	subDir := pathParts[slices.Index(pathParts, "yara")+1]

	words := []string{subDir}

	// ELASTIC_Linux_Trojan_Gafgyt_E4A1982B
	words = append(words, strings.Split(strings.ToLower(rule), "_")...)

	// strip off the last wold if it's a hex key
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

	key := fmt.Sprintf("3P/%s", strings.Join(keepWords, "/"))
	return strings.ReplaceAll(key, "signature/base", "signature_base")
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

	key := strings.ReplaceAll(src, "-", "/")
	return strings.ReplaceAll(key, ".yara", "")
}

func generateRuleURL(src string, rule string) string {
	// Linking to exact commit and line number would be ideal, but
	// we aren't parsing that information out of our YARA files yet
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

func behaviorRisk(ns string, rule string, tags []string) int {
	risk := 1

	if thirdParty(ns) {
		risk = 3
		src := strings.Split(ns, "/")[1]

		if thirdPartyCriticalSources[src] {
			risk = 4
			if strings.Contains(strings.ToLower(ns), "generic") || strings.Contains(strings.ToLower(rule), "generic") {
				risk = 3
			}
		}

		if strings.Contains(strings.ToLower(ns), "keyword") || strings.Contains(strings.ToLower(rule), "keyword") {
			risk = 2
		}
	}

	if strings.Contains(ns, "combo/") {
		risk = 2
	}

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
	for _, tag := range tags {
		if r, ok := levels[tag]; ok {
			risk = r
		}
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
	var longest []string

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

func matchToString(ruleName string, m yara.MatchString) string {
	s := string(m.Data)
	switch {
	case strings.Contains(ruleName, "base64") && !strings.Contains(s, "base64"):
		s = fmt.Sprintf("%s::%s", s, m.Name)
	case strings.Contains(ruleName, "xor") && !strings.Contains(s, "xor"):
		s = fmt.Sprintf("%s::%s", s, m.Name)
	case unprintableString(s):
		s = m.Name
	// bad hack, can we do this in YARA?
	case strings.Contains(m.Name, "xml_key_val"):
		s = strings.ReplaceAll(strings.ReplaceAll(s, "<key>", ""), "</key>", "")
	}
	return strings.TrimSpace(s)
}

// extract match strings.
func matchStrings(ruleName string, ms []yara.MatchString) []string {
	var raw []string

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
		Behaviors: []*bincapz.Behavior{},
	}

	var pledges []string
	var caps []string
	var syscalls []string

	overallRiskScore := 0
	riskCounts := map[int]int{}
	risk := 0
	key := ""

	for _, m := range mrs {
		risk = behaviorRisk(m.Namespace, m.Rule, m.Tags)
		if risk > overallRiskScore {
			overallRiskScore = risk
		}
		riskCounts[risk]++
		if risk < minScore {
			continue
		}
		key = generateKey(m.Namespace, m.Rule)
		ruleURL := generateRuleURL(m.Namespace, m.Rule)

		b := &bincapz.Behavior{
			ID:           key,
			MatchStrings: matchStrings(m.Rule, m.Strings),
			RiskLevel:    RiskLevels[risk],
			RiskScore:    risk,
			RuleURL:      ruleURL,
		}

		k := ""
		v := ""

		for _, meta := range m.Metas {
			k = meta.Identifier
			v = fmt.Sprintf("%s", meta.Value)
			// Empty data is unusual, so just ignore it.
			if k == "" || v == "" {
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
			case "__bincapz__":
				fr.IsBincapz = true
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

		if ignoreMatch(m.Tags, ignore) {
			fr.FilteredBehaviors++
			clog.DebugContextf(ctx, "dropping %s (tags match ignore list)", m.Namespace)
			continue
		}

		// If the rule does not have a description, make one up based on the rule name
		if b.Description == "" {
			b.Description = strings.ReplaceAll(m.Rule, "_", " ")
		}

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
				fr.Behaviors = append(fr.Behaviors[:existingIndex], append([]*bincapz.Behavior{b}, fr.Behaviors[existingIndex+1:]...)...)
			}
			if len(fr.Behaviors[existingIndex].Description) < len(b.Description) && fr.Behaviors[existingIndex].RiskScore <= b.RiskScore {
				fr.Behaviors[existingIndex].Description = b.Description
			}
		} else {
			fr.Behaviors = append(fr.Behaviors, b)
		}

		// TODO: If we match multiple rules within a single namespace, merge matchstrings
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

	return fr, nil
}
