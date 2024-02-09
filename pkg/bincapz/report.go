package bincapz

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

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
	if slices.Contains(tags, "risky") {
		risk = 2
	}
	if slices.Contains(tags, "suspicious") {
		risk = 3
	}
	return risk
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
		b := Behavior{
			Risk: behaviorRisk(m.Tags),
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
		} else {
			fr.Behaviors[key] = b
		}

		slices.Sort(pledges)
		slices.Sort(syscalls)
		slices.Sort(caps)
		fr.Pledge = slices.Compact(pledges)
		fr.Syscalls = slices.Compact(syscalls)
		fr.Capabililies = slices.Compact(caps)
	}
	klog.V(1).Infof("yara matches: %+v", mrs)
	return fr
}
