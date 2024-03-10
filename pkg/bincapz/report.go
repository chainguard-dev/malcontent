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
	Description string   `json:",omitempty" yaml:",omitempty"`
	Values      []string `json:",omitempty" yaml:",omitempty"`
	RiskScore   int
	RiskLevel   string `json:",omitempty" yaml:",omitempty"`
	RuleAuthor  string `json:",omitempty" yaml:",omitempty"`
	RuleLicense string `json:",omitempty" yaml:",omitempty"`
}

type FileReport struct {
	Path string
	// compiler -> x
	Error             string              `json:",omitempty" yaml:",omitempty"`
	Skipped           string              `json:",omitempty" yaml:",omitempty"`
	Meta              map[string]string   `json:",omitempty" yaml:",omitempty"`
	Syscalls          []string            `json:",omitempty" yaml:",omitempty"`
	Pledge            []string            `json:",omitempty" yaml:",omitempty"`
	Capabilities      []string            `json:",omitempty" yaml:",omitempty"`
	Behaviors         map[string]Behavior `json:",omitempty" yaml:",omitempty"`
	FilteredBehaviors int                 `json:",omitempty" yaml:",omitempty"`
}

type Report struct {
	Files  map[string]FileReport
	Filter string `json:",omitempty" yaml:",omitempty"`
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
	"linux":             true,
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

// extrach match strings, but only if the rule name or match variable indicate preservation
func matchValues(key string, ruleName string, ms []yara.MatchString) []string {
	raw := []string{}

	for _, m := range ms {
		keep := false

		switch {
		case strings.HasSuffix(m.Name, "val"):
			keep = true
		case strings.Contains(key, "combo/"):
			keep = true
		case strings.Contains(key, "ref/"):
			keep = true
		case strings.Contains(ruleName, "value"):
			keep = true
		}
		if !keep {
			continue
		}

		klog.Infof("keeping: %s - %s - %s: %s", key, ruleName, m.Name, m.Data)

		s := string(m.Data)
		if strings.Contains(ruleName, "base64") && !strings.Contains(s, "base64") {
			s = fmt.Sprintf("%s (%s)", s, m.Name)
		}
		if strings.Contains(ruleName, "xor") && !strings.Contains(s, "xor") {
			s = fmt.Sprintf("%s (%s)", s, m.Name)
		}

		if unprintableString(s) {
			s = m.Name
		}
		raw = append(raw, s)
	}

	slices.Sort(raw)
	longest := []string{}

	// inefficiently remove substring matches
	for _, s := range slices.Compact(raw) {
		if s == "" {
			continue
		}

		isLongest := true
		for _, o := range raw {
			if o != s && strings.Contains(o, s) {
				klog.Infof("%s contains %s", o, s)
				isLongest = false
				break
			}
		}
		if isLongest {
			longest = append(longest, s)
		}
	}
	klog.Infof("longest: %v", longest)

	slices.Sort(longest)
	return longest
}

func fileReport(path string, mrs yara.MatchRules, ignoreTags []string, minLevel int) FileReport {
	ignore := map[string]bool{}
	for _, t := range ignoreTags {
		ignore[t] = true
	}

	fr := FileReport{
		Path:      path,
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
		key := generateKey(m.Namespace, m.Rule)

		b := Behavior{
			RiskScore: risk,
			RiskLevel: riskLevels[risk],
			Values:    matchValues(key, m.Rule, m.Strings),
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
