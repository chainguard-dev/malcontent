// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/release"
	"github.com/puzpuzpuz/xsync/v4"

	yarax "github.com/VirusTotal/yara-x/go"
)

// malcontentMetaKey is the metadata key that marks malcontent's own rules.
const malcontentMetaKey = "__" + NAME + "__"

// ruleInfo holds everything a report derives from a rule's namespace,
// identifier, tags, and metadata. None of it depends on the scanned file, so
// one ruleInfo serves every match of the rule. Nothing modifies a ruleInfo
// after newRuleInfo returns it, which lets goroutines share it.
type ruleInfo struct {
	// behavior is the rule's behavior before per-file changes. Its Override
	// and MatchStrings fields stay nil.
	behavior malcontent.Behavior
	scope    ruleScope
	// order is the rule's index in its rule set's declaration order, which
	// fixes the order Generate processes matches in.
	order        int
	risk         int
	override     bool
	thirdParty   bool
	isMalcontent bool
	// meta/ rules describe the file through metaKey and metaValue instead of
	// adding a behavior.
	isMeta              bool
	metaKey             string
	metaValue           string
	fallbackDescription string
	pledges             []string
	caps                []string
	syscalls            []string
	// targets lists, in metadata order, the rules an override rule names.
	targets []overrideKey
}

// overrideKey is one directive of an override rule: set the rule named rule
// to score.
type overrideKey struct {
	rule  string
	score int
}

// newRuleInfo derives m's ruleInfo, building rule URLs against ref. order is
// m's declaration index within its rule set.
func newRuleInfo(m *yarax.Rule, ref string, order int) *ruleInfo {
	ns, id := m.Namespace(), m.Identifier()
	key := generateKey(ns, id)
	risk := matchRisk(m)
	ri := &ruleInfo{
		behavior: malcontent.Behavior{
			ID:        key,
			RiskLevel: RiskLevels[risk],
			RiskScore: risk,
			RuleName:  id,
			RuleURL:   generateRuleURL(ref, ns, id),
		},
		scope:               newRuleScope(m.Metadata()),
		order:               order,
		risk:                risk,
		override:            slices.Contains(m.Tags(), "override"),
		thirdParty:          thirdParty(ns),
		fallbackDescription: strings.ReplaceAll(id, "_", " "),
	}
	if strings.HasPrefix(key, "meta/") {
		ri.isMeta = true
		ri.metaKey = strings.ReplaceAll(filepath.Dir(key), "meta/", "")
		ri.metaValue = filepath.Base(key)
	}
	ri.applyMetadata(m.Metadata())
	return ri
}

// applyMetadata records the behavior fields, file attributes, and override
// directives that a rule's metadata declares.
func (ri *ruleInfo) applyMetadata(meta []yarax.Metadata) {
	b := &ri.behavior
	for i := range meta {
		// YARA requires a metadata identifier, so only the value can be
		// empty. Empty data is unusual, so just ignore it.
		k := meta[i].Identifier()
		v := metaString(meta[i].Value())
		if v == "" {
			continue
		}

		switch k {
		case "author":
			b.RuleAuthor = v
			if m := authorWithURLRe.FindStringSubmatch(v); m != nil && isValidURL(m[2]) {
				b.RuleAuthor = m[1]
				b.RuleAuthorURL = m[2]
			}
			// If author is in @username format, strip @ to avoid constantly pinging them on GitHub
			b.RuleAuthor = strings.TrimPrefix(b.RuleAuthor, "@")
		case "author_url":
			b.RuleAuthorURL = v
		case malcontentMetaKey:
			if v == "true" {
				ri.isMalcontent = true
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
			ri.pledges = append(ri.pledges, v)
		case "syscall":
			ri.syscalls = append(ri.syscalls, strings.Split(v, ",")...)
		case "cap":
			ri.caps = append(ri.caps, v)
		case "filetypes", "severity", "path_include", "path_exclude", "identifies", "mitre_tactics", "specificity", "sophistication", "max_hits":
			// Scoping and classification metadata (e.g. GuardDog). severity
			// is applied via matchRisk and the scoping keys via ruleScope; the
			// rest are informational and must not be treated as override
			// directives.
		default:
			// Any other key of an override rule names the rule to override.
			// Whether that rule matched is known only per file.
			if ri.override {
				ri.targets = append(ri.targets, overrideKey{rule: k, score: Levels[v]})
			}
		}
	}
}

// metaString renders a metadata value the way the "%s" verb does.
func metaString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%s", v)
}

// ruleID identifies a rule within one compiled rule set.
type ruleID struct {
	namespace  string
	identifier string
}

// ruleInfoCacheSlots bounds how many rule sets keep cached rule information.
// Callers normally use one rule set; a few slots spare callers that alternate
// between sets, such as concurrent tests, from rebuilding it on every call.
const ruleInfoCacheSlots = 8

var (
	ruleInfoCachesMu sync.Mutex
	// ruleInfoCaches lists the caches, most recently added first. It is
	// replaced under ruleInfoCachesMu and never modified, so readers only
	// load it.
	ruleInfoCaches atomic.Pointer[[]*ruleInfoCache]
)

// ruleInfoCache holds the ruleInfo of every rule of one rule set that has
// matched so far, with rule URLs built against ref.
type ruleInfoCache struct {
	// rules is weak so that the cache never keeps a rule set alive; once the
	// set is collected, the cache serves no caller and is dropped.
	rules weak.Pointer[yarax.Rules]
	ref   string
	infos *xsync.Map[ruleID, *ruleInfo]
	// order maps each rule to its declaration index. Listing the rules is
	// expensive, so it happens once, when the first rule is looked up.
	orderOnce sync.Once
	order     map[ruleID]int
}

// ruleInfos looks up the ruleInfo of matching rules.
type ruleInfos struct {
	ref   string
	rules *yarax.Rules
	// cache is nil when the rule set is unknown. Rules are then derived on
	// every lookup, because a namespace and identifier only identify a rule
	// within one rule set, and their declaration order is unknown.
	cache *ruleInfoCache
}

// ruleInfosFor returns the ruleInfo lookup for rules from yrs, which may be
// nil when the caller does not know the rule set.
func ruleInfosFor(yrs *yarax.Rules) ruleInfos {
	ref := release.ResolveRuleURLCommit()
	if yrs == nil {
		return ruleInfos{ref: ref}
	}
	if c := findRuleInfoCache(yrs, ref); c != nil {
		return ruleInfos{ref: ref, rules: yrs, cache: c}
	}

	ruleInfoCachesMu.Lock()
	defer ruleInfoCachesMu.Unlock()
	// Another caller may have added the cache while this one waited.
	if c := findRuleInfoCache(yrs, ref); c != nil {
		return ruleInfos{ref: ref, rules: yrs, cache: c}
	}
	fresh := &ruleInfoCache{rules: weak.Make(yrs), ref: ref, infos: xsync.NewMap[ruleID, *ruleInfo]()}
	next := append(make([]*ruleInfoCache, 0, ruleInfoCacheSlots), fresh)
	if cur := ruleInfoCaches.Load(); cur != nil {
		for _, c := range *cur {
			if len(next) == ruleInfoCacheSlots {
				break
			}
			// Drop the caches of collected rule sets.
			if c.rules.Value() != nil {
				next = append(next, c)
			}
		}
	}
	ruleInfoCaches.Store(&next)
	return ruleInfos{ref: ref, rules: yrs, cache: fresh}
}

// findRuleInfoCache returns the cache of rules from yrs with URLs built
// against ref, or nil.
func findRuleInfoCache(yrs *yarax.Rules, ref string) *ruleInfoCache {
	cur := ruleInfoCaches.Load()
	if cur == nil {
		return nil
	}
	for _, c := range *cur {
		if c.ref == ref && c.rules.Value() == yrs {
			return c
		}
	}
	return nil
}

// ruleOrders holds, for rule sets whose declaration order was recorded with
// SetRuleOrder, the function that gives each rule's declaration index.
var ruleOrders = xsync.NewMap[*yarax.Rules, func(namespace, identifier string) (int, bool)]()

// SetRuleOrder records how to find the declaration index of the rules that
// reports read with c.Rules set to yrs, which spares listing every rule of
// yrs and also covers rules compiled into other rule sets alongside yrs, as
// GenerateRules may receive.
func SetRuleOrder(yrs *yarax.Rules, order func(namespace, identifier string) (int, bool)) {
	ruleOrders.Store(yrs, order)
}

// orderOf returns the declaration index of the rule id from yrs.
func (c *ruleInfoCache) orderOf(yrs *yarax.Rules, id ruleID) (int, bool) {
	if order, ok := ruleOrders.Load(yrs); ok {
		return order(id.namespace, id.identifier)
	}
	c.orderOnce.Do(func() { c.order = declarationOrder(yrs) })
	idx, ok := c.order[id]
	return idx, ok
}

// declarationOrder maps each rule of yrs to its index in declaration order,
// the order in which a fresh scanner reports matches.
func declarationOrder(yrs *yarax.Rules) map[ruleID]int {
	all := yrs.Slice()
	order := make(map[ruleID]int, len(all))
	for i, r := range all {
		order[ruleID{namespace: r.Namespace(), identifier: r.Identifier()}] = i
	}
	return order
}

// get returns m's ruleInfo.
func (ris ruleInfos) get(m *yarax.Rule) *ruleInfo {
	if ris.cache == nil {
		return newRuleInfo(m, ris.ref, -1)
	}
	return ris.cache.get(ris.rules, m)
}

// ordered reports whether ris knows the declaration order of the rules.
func (ris ruleInfos) ordered() bool {
	return ris.cache != nil
}

// get returns the ruleInfo of m, a rule from yrs, deriving and storing it on
// first use.
func (c *ruleInfoCache) get(yrs *yarax.Rules, m *yarax.Rule) *ruleInfo {
	id := ruleID{namespace: m.Namespace(), identifier: m.Identifier()}
	if ri, ok := c.infos.Load(id); ok {
		return ri
	}
	idx, ok := c.orderOf(yrs, id)
	if !ok {
		// Only a rule from another rule set can be missing; it sorts after
		// every declared rule, in the order yara-x reported it.
		idx = len(c.order)
	}
	// Concurrent callers may both derive the ruleInfo; they are identical,
	// and the first one stored wins.
	ri, _ := c.infos.LoadOrStore(id, newRuleInfo(m, c.ref, idx))
	return ri
}

// ruleScope is a rule's type and path scoping: malcontent's "filetypes" (an
// extension list) and the third-party "path_include"/"path_exclude" keys
// (comma-separated path globs, e.g. from GuardDog). A rule that declares none
// of these applies to every file. When a key repeats, the last one counts.
type ruleScope struct {
	filetypes    []string
	include      []*glob
	includeTypes []string
	// exclude is empty when the rule declares no path_exclude, which then
	// excludes nothing.
	exclude      []*glob
	hasFiletypes bool
	hasInclude   bool
}

// newRuleScope extracts the scoping declared by a rule's metadata.
func newRuleScope(meta []yarax.Metadata) ruleScope {
	values := map[string]string{}
	for i := range meta {
		if k := meta[i].Identifier(); k == "filetypes" || k == "path_include" || k == "path_exclude" {
			values[k] = metaString(meta[i].Value())
		}
	}
	return scopeFromValues(values)
}

// matches reports whether a rule with this scope applies to a file of the
// detected extension ext at the slash-separated path.
func (s *ruleScope) matches(ext string, path string) bool {
	// Path globs are only meaningful when we have a path; a pathless (in-memory)
	// scan leaves them unevaluated so the rule stays universal.
	if path != "" {
		if matchesAny(s.exclude, path) {
			return false
		}
		// A path_include rule applies when the path matches, or when the
		// detected file type matches one of its "*.ext" globs (covering
		// extensionless files whose type malcontent identified by content).
		if s.hasInclude && !matchesAny(s.include, path) &&
			(ext == "" || !extMatchesTypes(s.includeTypes, ext)) {
			return false
		}
	}

	// An undetected file type is treated as universal, preserving the
	// behavior from before the path-glob keys were introduced.
	if !s.hasFiletypes || ext == "" {
		return true
	}
	return extMatchesTypes(s.filetypes, ext)
}

// extAliases maps a detected file extension to additional filetypes that
// rules may be scoped to. Compiled Java bytecode is usually scanned as a
// bare .class file after archive extraction, so rules scoped to jar or
// java sources must also apply to it. Likewise, compiled Python bytecode
// is detected by content as pyc regardless of the file's extension, so
// rules scoped to py sources must also apply to it.
var extAliases = map[string][]string{
	extClass: {"jar", "java"},
	extPyc:   {"py"},
}

// extMatchesTypes reports whether a detected file extension is one of a
// rule's filetypes, either verbatim or through an extension alias.
func extMatchesTypes(types []string, ext string) bool {
	if slices.Contains(types, ext) {
		return true
	}
	for _, alias := range extAliases[ext] {
		if slices.Contains(types, alias) {
			return true
		}
	}
	return false
}

// globExtensions extracts the bare file extensions from "*.ext" entries in a
// comma-separated path-glob list, ignoring path-shaped globs ("*/setup.py",
// "dist/*"). The result is a filetypes-style list, so a path_include can also
// be satisfied by the detected file type when the path itself lacks the
// expected extension.
func globExtensions(patterns string) string {
	var exts []string
	for p := range strings.SplitSeq(patterns, ",") {
		p = strings.TrimSpace(p)
		if rest, ok := strings.CutPrefix(p, "*."); ok && rest != "" && !strings.ContainsAny(rest, "/*") {
			exts = append(exts, rest)
		}
	}
	return strings.Join(exts, ",")
}
