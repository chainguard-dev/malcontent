package bincapz

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

var riskLevels = map[int]string{
	0: "NONE", // harmless: common to all executables, no system impact
	1: "LOW",  // undefined: low impact, common to good and bad executables
	2: "MED",  // notable: may have impact, but common
	3: "HIGH", // suspicious: uncommon, but could be legit
	4: "CRIT", // critical: certainly malware
}

type Behavior struct {
	Description string `json:",omitempty" yaml:",omitempty"`
	Strings     []string
	RiskScore   int
	RiskLevel   string
	RuleAuthor  string
	RuleLicense string
}

type FileReport struct {
	// compiler -> x
	Error             string
	Skipped           string
	Meta              map[string]string
	Syscalls          []string
	Pledge            []string
	Capabilities      []string
	Behaviors         map[string]Behavior
	FilteredBehaviors int `json:",omitempty" yaml:",omitempty"`
}

type Report struct {
	Files  map[string]FileReport
	Filter string
}

// yaraForge has some very very long rule names
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

func generateKey(src string, rule string) string {
	// It's Yara FORGE
	if strings.Contains(src, "yara-rules") {
		return yaraForgeKey(rule)
	}

	_, after, _ := strings.Cut(src, "third_party/")
	if after != "" {
		key := strings.ReplaceAll(after, "-", "/")
		key = strings.ReplaceAll(key, "/rules", "")
		key = strings.ReplaceAll(key, "/yara", "")
		return "third_party/" + strings.ReplaceAll(key, ".yar", "")
	}

	_, after, _ = strings.Cut(src, "rules/")
	key := strings.ReplaceAll(after, "-", "/")
	return strings.ReplaceAll(key, ".yara", "")
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

	// In case we forget to add a tag
	if strings.Contains(ns, "combo/") {
		risk = 2
	}

	if slices.Contains(tags, "harmless") {
		risk = 0
	}
	if slices.Contains(tags, "notable") {
		risk = 2
	}
	if slices.Contains(tags, "medium") {
		risk = 2
	}

	if slices.Contains(tags, "suspicious") {
		risk = 3
	}
	if slices.Contains(tags, "weird") {
		risk = 3
	}
	if slices.Contains(tags, "high") {
		risk = 3
	}

	if slices.Contains(tags, "crit") {
		risk = 4
	}
	if slices.Contains(tags, "critical") {
		risk = 4
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

func matchStrings(ms []yara.MatchString) []string {
	ss := []string{}
	lastS := ""
	for _, m := range ms {
		s := string(m.Data)
		if unprintableString(s) {
			s = m.Name
		}
		if lastS != "" && strings.Contains(lastS, s) {
			continue
		}
		ss = append(ss, s)
	}
	slices.Sort(ss)
	return slices.Compact(ss)
}

func fileReport(mrs yara.MatchRules, ignoreTags []string, minLevel int) FileReport {
	ignore := map[string]bool{}
	for _, t := range ignoreTags {
		ignore[t] = true
	}

	fr := FileReport{
		Meta:      map[string]string{},
		Behaviors: map[string]Behavior{},
	}

	pledges := []string{}
	caps := []string{}
	syscalls := []string{}
	desc := ""
	author := ""
	license := ""

	for _, m := range mrs {
		risk := behaviorRisk(m.Namespace, m.Tags)
		if risk < minLevel {
			continue
		}
		b := Behavior{
			RiskScore: risk,
			RiskLevel: riskLevels[risk],
			Strings:   matchStrings(m.Strings),
		}

		for _, meta := range m.Metas {
			switch meta.Identifier {
			case "author":
				author = fmt.Sprintf("%s", meta.Value)
				if len(author) > len(b.RuleAuthor) {
					b.RuleAuthor = author
				}

			case "license", "license_url":
				license = fmt.Sprintf("%s", meta.Value)
				if len(license) > len(b.RuleLicense) {
					b.RuleLicense = license
				}

			case "description", "threat_name", "name":
				desc = fmt.Sprintf("%s", meta.Value)
				if len(desc) > len(b.Description) {
					b.Description = desc
				}
			case "pledge":
				pledges = append(pledges, fmt.Sprintf("%s", meta.Value))
			case "syscall":
				sy := strings.Split(fmt.Sprintf("%s", meta.Value), ",")
				syscalls = append(syscalls, sy...)
			case "cap":
				caps = append(caps, fmt.Sprintf("%s", meta.Value))
			}
		}

		key := generateKey(m.Namespace, m.Rule)
		if strings.HasPrefix(key, "meta/") {
			k := filepath.Dir(key)
			v := filepath.Base(key)
			fr.Meta[strings.ReplaceAll(k, "meta/", "")] = v
			continue
		}
		if ignoreMatch(m.Tags, ignore) {
			fr.FilteredBehaviors++
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

	slices.Sort(pledges)
	slices.Sort(syscalls)
	slices.Sort(caps)
	fr.Pledge = slices.Compact(pledges)
	fr.Syscalls = slices.Compact(syscalls)
	fr.Capabilities = slices.Compact(caps)

	klog.V(4).Infof("yara matches: %+v", mrs)
	return fr
}
