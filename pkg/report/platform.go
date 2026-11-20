// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"slices"
	"strings"

	yarax "github.com/VirusTotal/yara-x/go"
)

// platformWords maps the words third-party rules use to name an operating
// system, in their "os" metadata or their identifiers, to the platform tag
// first-party rules use for it. Words are lowercase. Ambiguous words are left
// out: "mac" also names MAC addresses and MAC times, "elf" and "unix" cover
// several platforms, and "solaris" and "apple" are also malware names.
var platformWords = map[string]string{
	"darwin":  tagMacOS,
	"linux":   tagLinux,
	"lnx":     tagLinux,
	"macos":   tagMacOS,
	"osx":     tagMacOS,
	"win":     tagWindows,
	"win32":   tagWindows,
	"win64":   tagWindows,
	"windows": tagWindows,
}

// osMetaKey is the metadata key that Elastic and Volexity rules use to name
// the operating systems they target, such as "windows", "win,linux", or
// "multi".
const osMetaKey = "os"

// platformTags returns the platform tags, in the order their words appear,
// of a third-party rule named id with metadata meta. Third-party rules do not
// use malcontent's platform tags, so they are inferred: from the rule's "os"
// metadata when it has any, since that is the vendor's own statement and may
// say that the rule covers every platform, and otherwise from the
// underscore-separated words of its identifier, as in
// ELASTIC_Linux_Trojan_Gafgyt or SIGNATURE_BASE_APT_MAL_LNX_Kobalos.
func platformTags(id string, meta []yarax.Metadata) []string {
	var tags []string
	add := func(word string) {
		if tag, ok := platformWords[strings.ToLower(strings.TrimSpace(word))]; ok && !slices.Contains(tags, tag) {
			tags = append(tags, tag)
		}
	}
	declared := false
	for i := range meta {
		if meta[i].Identifier() != osMetaKey {
			continue
		}
		declared = true
		for word := range strings.SplitSeq(metaString(meta[i].Value()), ",") {
			add(word)
		}
	}
	if declared {
		return tags
	}
	for word := range strings.SplitSeq(id, "_") {
		add(word)
	}
	return tags
}

// withPlatformTags returns tags with each of platforms it lacks appended. It
// never modifies the array behind tags, which belongs to the compiled rule.
func withPlatformTags(tags []string, platforms []string) []string {
	// A clipped slice has no spare capacity, so the first append copies it.
	out := slices.Clip(tags)
	for _, p := range platforms {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}
