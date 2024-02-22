package bincapz

import (
	"fmt"
	"path/filepath"
	"slices"
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
}

type FileReport struct {
	// compiler -> x
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

func generateKey(src string) string {
	_, after, _ := strings.Cut(src, "rules/")
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

func behaviorRisk(tags []string) int {
	risk := 1
	if slices.Contains(tags, "harmless") {
		risk = 0
	}
	if slices.Contains(tags, "notable") {
		risk = 2
	}
	if slices.Contains(tags, "suspicious") {
		risk = 3
	}
	if slices.Contains(tags, "critical") {
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

func fileReport(mrs yara.MatchRules, ignoreTags []string) FileReport {
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

	for _, m := range mrs {
		risk := behaviorRisk(m.Tags)
		b := Behavior{
			RiskScore: risk,
			RiskLevel: riskLevels[risk],
			Strings:   matchStrings(m.Strings),
		}

		for _, meta := range m.Metas {
			switch meta.Identifier {
			case "description":
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

		key := generateKey(m.Namespace)
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

	klog.V(1).Infof("yara matches: %+v", mrs)
	return fr
}
