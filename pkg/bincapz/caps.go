package bincapz

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hillu/go-yara/v4"
	"k8s.io/klog/v2"
)

func generateKey(c Capability) string {
	_, after, _ := strings.Cut(c.RuleSource, "rules/")
	key := strings.ReplaceAll(after, "-", "/")
	return strings.ReplaceAll(key, ".yara", "")
}

func ignoreMatch(m yara.MatchRule, ignoreTags map[string]bool) bool {
	for _, t := range m.Tags {
		if ignoreTags[t] {
			return true
		}
	}
	return false
}

func matchToCapabilities(mrs yara.MatchRules, ignoreTags []string) []Capability {
	ignore := map[string]bool{}
	for _, t := range ignoreTags {
		ignore[t] = true
	}

	caps := []Capability{}
	for _, m := range mrs {
		if ignoreMatch(m, ignore) {
			continue
		}

		data := []string{}
		for _, st := range m.Strings {
			data = append(data, string(st.Data))
		}
		slices.Sort(data)
		c := Capability{
			Rule:       m.Rule,
			RuleSource: m.Namespace,
			Matched:    slices.Compact(data),
		}

		for _, meta := range m.Metas {
			switch meta.Identifier {
			case "description":
				c.Description = fmt.Sprintf("%s", meta.Value)
			case "pledge":
				c.Pledge = fmt.Sprintf("%s", meta.Value)
			case "syscall":
				c.Syscall = fmt.Sprintf("%s", meta.Value)
			}
		}

		c.Key = generateKey(c)
		caps = append(caps, c)
	}
	klog.V(1).Infof("yara matches: %+v", mrs)
	return caps
}
