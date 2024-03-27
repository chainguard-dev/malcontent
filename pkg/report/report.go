package report

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

var riskLevels = map[int]string{
	0: "NONE",     // harmless: common to all executables, no system impact
	1: "LOW",      // undefined: low impact, common to good and bad executables
	2: "MEDIUM",   // notable: may have impact, but common
	3: "HIGH",     // suspicious: uncommon, but could be legit
	4: "CRITICAL", // critical: certainly malware
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
	"macos":             true,
	"osx":               true,
	"mac":               true,
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
				klog.Infof("%s contains %s", o, s)
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

// convert MatchString to a usable string
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

// extract important values
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
		case strings.Contains(key, "xor/"):
			keep = true
		case strings.Contains(key, "base64/"):
			keep = true
		case strings.Contains(ruleName, "value"):
			keep = true
		case strings.HasSuffix(ruleName, "val"):
			keep = true
		}
		if !keep {
			continue
		}

		klog.Infof("keeping: %s - %s - %s: %s", key, ruleName, m.Name, m.Data)
		raw = append(raw, matchToString(ruleName, m))
	}

	slices.Sort(raw)
	return longestUnique(raw)
}

// extract match strings
func matchStrings(ruleName string, ms []yara.MatchString) []string {
	raw := []string{}

	for _, m := range ms {
		raw = append(raw, matchToString(ruleName, m))
	}

	slices.Sort(raw)
	return longestUnique(raw)
}

func pathChecksum(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("err-%v", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

func Generate(path string, mrs yara.MatchRules, ignoreTags []string, minScore int) bincapz.FileReport {
	ignore := map[string]bool{}
	for _, t := range ignoreTags {
		ignore[t] = true
	}

	fr := bincapz.FileReport{
		Path:      path,
		SHA256:    pathChecksum(path),
		Meta:      map[string]string{},
		Behaviors: map[string]bincapz.Behavior{},
	}

	pledges := []string{}
	caps := []string{}
	syscalls := []string{}
	desc := ""
	author := ""
	license := ""
	overallRiskScore := 0
	riskCounts := map[int]int{}

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

		b := bincapz.Behavior{
			RiskScore:    risk,
			RiskLevel:    riskLevels[risk],
			Values:       matchValues(key, m.Rule, m.Strings),
			MatchStrings: matchStrings(m.Rule, m.Strings),
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
	fr.RiskLevel = riskLevels[fr.RiskScore]

	klog.V(4).Infof("yara matches: %+v", mrs)
	return fr
}
