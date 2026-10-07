// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/sha256-simd"
	"golang.org/x/sync/errgroup"

	"github.com/chainguard-dev/malcontent/pkg/file"

	yarax "github.com/VirusTotal/yara-x/go"
)

// A rule's scope is the file types and paths its metadata limits it to
// ("filetypes", "path_include", "path_exclude"). Reports discard matches of a
// rule outside its scope, so scanning a file with such rules is wasted work,
// and a few of them are expensive on content they were never meant for. A
// Split compiles the rules that apply everywhere into one rule set and keeps
// the scoped rules aside, to be compiled into small sets holding only the
// rules that apply to the file being scanned.
//
// Many rules also require a file to start with some header, such as the "MZ"
// of a PE file, through a condition of the form uint16(0) == 0x5a4d and ...;
// no other file can match them. A Split compiles these rules into one set per
// header, for files that start with it.

// RuleKey identifies a rule: the namespace it was compiled in (its file's
// path) and its identifier.
type RuleKey struct {
	Namespace  string
	Identifier string
}

// ScopedRule is a rule set aside from the universal rules because its
// metadata scopes it, with the raw values of its scoping metadata. A key that
// a rule does not declare is absent from Meta.
type ScopedRule struct {
	Key  RuleKey
	Meta map[string]string
	file int
	rule int
}

// Split is a rule set divided by scope. Scanning a file with Universal and
// with the set CompileScoped builds for the scoped rules that apply to it
// matches exactly the rules a scan with every rule matches, apart from scoped
// rules that do not apply, which reports discard.
type Split struct {
	// Universal holds every rule that is not set aside.
	Universal *yarax.Rules
	// Scoped lists the rules set aside, in declaration order.
	Scoped []ScopedRule
	// Order is the declaration index of every rule, the order in which a
	// fresh scanner of the complete rule set reports matches.
	Order map[RuleKey]int
	// ByHeader maps the first two bytes of a file to the rules set aside
	// because they require a file to start with them, with the rules they
	// refer to. A file that starts otherwise matches none of them.
	ByHeader map[[2]byte]*HeaderRules

	files []splitFile
	// cacheName names the cache file of Universal when the split is cached;
	// CompileScoped caches the sets it compiles beside it.
	cacheName string
}

// HeaderRules is the rule set of the rules that require one header. A set
// loaded from the cache is read on first use.
type HeaderRules struct {
	once  sync.Once
	data  []byte
	rules *yarax.Rules
	err   error
}

// Load returns the rule set.
func (h *HeaderRules) Load() (*yarax.Rules, error) {
	h.once.Do(func() {
		if h.rules == nil {
			h.rules, h.err = yarax.ReadFrom(bytes.NewReader(h.data))
		}
		h.data = nil
	})
	return h.rules, h.err
}

// splitFile is one rule file divided into rules.
type splitFile struct {
	namespace string
	imports   []string
	rules     []splitRule
	// global reports whether the file declares a global rule, which every
	// other rule of the file depends on.
	global bool
}

// splitRule is the source of one rule and the rules of its file that its
// condition refers to, by index.
type splitRule struct {
	name   string
	text   string
	refers []int
	scoped bool
	// gated reports whether the rule is set aside for the files that start
	// with header.
	gated  bool
	header [2]byte
}

var (
	ruleStartRE = regexp.MustCompile(`(?m)^[ \t]*((?:private|global)[ \t]+)*rule[ \t]+(\w+)([^{\n]*)`)
	importRE    = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+"(\w+)"`)
	scopeKeyRE  = regexp.MustCompile(`(?m)^[ \t]*(filetypes|path_include|path_exclude)[ \t]*=[ \t]*"((?:[^"\\\n]|\\.)*)"`)
	metaKeyRE   = regexp.MustCompile(`(?m)^[ \t]*(\w+)[ \t]*=`)
	identRE     = regexp.MustCompile(`[$#@!.]?\b[A-Za-z_]\w*\b\*?`)
	// parsingModuleRE finds modules that parse the whole file when a rule set
	// imports them. A rule using one stays universal, so that no file is
	// parsed twice.
	parsingModuleRE = regexp.MustCompile(`\b(elf|macho|pe|dotnet|lnk|dex|crx)\.`)
)

// overrideKnownKeys are the metadata keys of an override rule that are not
// names of rules it overrides.
var overrideKnownKeys = map[string]struct{}{
	"author": {}, "author_url": {}, "description": {}, "threat_name": {}, "name": {},
	"license": {}, "license_url": {}, "ref": {}, "reference": {}, "source_url": {},
	"pledge": {}, "syscall": {}, "cap": {}, "filetypes": {}, "severity": {},
	"path_include": {}, "path_exclude": {}, "identifies": {}, "mitre_tactics": {},
	"specificity": {}, "sophistication": {}, "max_hits": {},
}

// selfRule names the rule that identifies malcontent itself; reports read it
// before scoping, so it is never set aside.
const selfRule = "malcontent"

// RecursiveSplit compiles the rules in fss divided by scope. It reads and
// preprocesses the sources as Recursive does.
func RecursiveSplit(ctx context.Context, fss []fs.FS) (*Split, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	files, err := readSplitFiles(ctx, fss)
	if err != nil {
		return nil, err
	}
	markScoped(files)

	sets := headerSets(files)
	s := &Split{files: files, Order: map[RuleKey]int{}, ByHeader: make(map[[2]byte]*HeaderRules, len(sets))}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))
	g.Go(func() error {
		var err error
		s.Universal, err = compileFiles(gctx, files, func(fi, ri int) bool {
			r := files[fi].rules[ri]
			return !r.scoped && !r.gated
		})
		if err != nil {
			return fmt.Errorf("compile universal rules: %w", err)
		}
		return nil
	})
	for head, want := range sets {
		h := &HeaderRules{}
		s.ByHeader[head] = h
		g.Go(func() error {
			var err error
			h.rules, err = compileFiles(gctx, files, func(fi, ri int) bool {
				_, ok := want[fi][ri]
				return ok
			})
			if err != nil {
				return fmt.Errorf("compile rules for header %q: %w", head[:], err)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	for fi, f := range files {
		for ri, r := range f.rules {
			key := RuleKey{Namespace: f.namespace, Identifier: r.name}
			s.Order[key] = len(s.Order)
			if r.scoped {
				s.Scoped = append(s.Scoped, ScopedRule{Key: key, Meta: scopeMeta(r.text), file: fi, rule: ri})
			}
		}
	}
	return s, nil
}

// readSplitFiles reads every rule file in fss, in compile order, and divides
// each into rules.
func readSplitFiles(ctx context.Context, fss []fs.FS) ([]splitFile, error) {
	remover := defaultRuleRemover()
	var files []splitFile
	for _, root := range fss {
		err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() || !isRuleFile(path) {
				return nil
			}
			bs, err := fs.ReadFile(root, path)
			if err != nil {
				return fmt.Errorf("readfile: %w", err)
			}
			files = append(files, parseSplitFile(path, remover.remove(bs)))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

// parseSplitFile divides the source of one rule file into its imports and
// rules. Each rule runs from its declaration to the next one.
func parseSplitFile(namespace string, src []byte) splitFile {
	f := splitFile{namespace: namespace}
	starts := ruleStartRE.FindAllSubmatchIndex(src, -1)
	for _, m := range importRE.FindAllSubmatch(src, -1) {
		if imp := string(m[1]); !slices.Contains(f.imports, imp) {
			f.imports = append(f.imports, imp)
		}
	}
	names := make(map[string]int, len(starts))
	for i, m := range starts {
		end := len(src)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		name := string(src[m[4]:m[5]])
		names[name] = i
		if bytes.Contains(src[m[0]:m[4]], []byte("global")) {
			f.global = true
		}
		f.rules = append(f.rules, splitRule{name: name, text: string(src[m[0]:end])})
	}
	for i := range f.rules {
		f.rules[i].refers = references(f.rules[i].text, f.rules[i].name, names)
	}
	return f
}

// references returns the rules of the same file, by index, that a rule's
// condition names, including rule sets such as (prefix*).
func references(text, self string, names map[string]int) []int {
	cond := text
	if _, after, ok := strings.Cut(text, "condition:"); ok {
		cond = after
	}
	var out []int
	for _, tok := range identRE.FindAllString(cond, -1) {
		if strings.ContainsAny(tok[:1], "$#@!.") {
			continue
		}
		if prefix, ok := strings.CutSuffix(tok, "*"); ok {
			for name, i := range names {
				if name != self && strings.HasPrefix(name, prefix) {
					out = append(out, i)
				}
			}
			continue
		}
		if i, ok := names[tok]; ok && tok != self {
			out = append(out, i)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// markScoped sets aside each rule that requires a header or that its
// metadata scopes, when nothing requires it among the universal rules: no
// universal rule refers to it, no override rule names it, it does not use a
// module that parses the file, no global rule shares its file, and it is not
// the rule that identifies malcontent. A rule that requires a header goes to
// that header's set even when its metadata scopes it, since reports discard
// matches outside its scope.
func markScoped(files []splitFile) {
	targets := overrideTargets(files)
	for fi := range files {
		f := &files[fi]
		parses := parsingRules(f.rules)
		for ri := range f.rules {
			r := &f.rules[ri]
			_, target := targets[r.name]
			if f.global || target || r.name == selfRule || parses[ri] {
				continue
			}
			r.header, r.gated = headerOf(r.text)
			r.scoped = !r.gated && scopeKeyRE.MatchString(metaSection(r.text))
		}
		// A universal rule keeps everything it refers to universal, directly
		// or through other rules.
		for changed := true; changed; {
			changed = false
			for _, r := range f.rules {
				if r.scoped || r.gated {
					continue
				}
				for _, i := range r.refers {
					if f.rules[i].scoped || f.rules[i].gated {
						f.rules[i].scoped, f.rules[i].gated = false, false
						changed = true
					}
				}
			}
		}
	}
}

// headerSets returns, for each header that rules require, the rules of each
// file its set holds: the rules that require it and the rules they refer to.
func headerSets(files []splitFile) map[[2]byte][]map[int]struct{} {
	out := map[[2]byte][]map[int]struct{}{}
	for fi, f := range files {
		for ri, r := range f.rules {
			if !r.gated {
				continue
			}
			want, ok := out[r.header]
			if !ok {
				want = make([]map[int]struct{}, len(files))
				out[r.header] = want
			}
			include(want, files, fi, ri)
		}
	}
	return out
}

// headerReads maps the functions that read an integer at a file offset to
// how many bytes they read and whether they read big-endian.
var headerReads = map[string]struct {
	width     int
	bigEndian bool
}{
	"uint16": {2, false}, "uint32": {4, false},
	"uint16be": {2, true}, "uint32be": {4, true},
}

// headerOf returns the first two bytes a file must start with for the rule
// whose source is text to match it. A rule requires a header when its whole
// condition is a chain of "and" with a check such as uint16(0) == 0x5a4d as
// one operand. On a file shorter than the check reads, the check is
// undefined, which fails the chain as well.
func headerOf(text string) ([2]byte, bool) {
	toks, ok := conditionTokens(text)
	if !ok {
		return [2]byte{}, false
	}
	for _, operand := range conjuncts(toks) {
		if head, ok := headerCheck(operand); ok {
			return head, true
		}
	}
	return [2]byte{}, false
}

// headerCheck returns the first two bytes of the header that operand, the
// tokens of a check such as uint16(0) == 0x5a4d, requires.
func headerCheck(operand []string) ([2]byte, bool) {
	operand = stripParens(operand)
	if len(operand) != 6 || operand[1] != "(" || operand[3] != ")" || operand[4] != "==" {
		return [2]byte{}, false
	}
	read, ok := headerReads[operand[0]]
	if !ok {
		return [2]byte{}, false
	}
	if off, ok := parseNumber(operand[2]); !ok || off != 0 {
		return [2]byte{}, false
	}
	v, ok := parseNumber(operand[5])
	if !ok || v>>(8*read.width) != 0 {
		return [2]byte{}, false
	}
	var b [8]byte
	if read.bigEndian {
		binary.BigEndian.PutUint64(b[:], v<<(64-8*read.width))
	} else {
		binary.LittleEndian.PutUint64(b[:], v)
	}
	return [2]byte(b[:2]), true
}

// parseNumber parses a YARA integer literal: decimal, 0x hexadecimal, or 0o
// octal.
func parseNumber(tok string) (uint64, bool) {
	base := 10
	if digits, ok := strings.CutPrefix(tok, "0x"); ok {
		tok, base = digits, 16
	} else if digits, ok := strings.CutPrefix(tok, "0o"); ok {
		tok, base = digits, 8
	}
	v, err := strconv.ParseUint(tok, base, 64)
	return v, err == nil && !strings.Contains(tok, "_")
}

// conditionTokens returns the tokens of the condition of the rule whose
// source is text, without comments: the tokens after its "condition:" up to
// the rule's closing brace. A string or regular expression is one token, so
// the words it holds are never taken for operators.
func conditionTokens(text string) ([]string, bool) {
	var toks []string
	start := -1
	for i := 0; i < len(text); {
		if strings.HasPrefix(text[i:], "//") {
			j := strings.IndexByte(text[i:], '\n')
			if j < 0 {
				break
			}
			i += j
			continue
		}
		if strings.HasPrefix(text[i:], "/*") {
			j := strings.Index(text[i+2:], "*/")
			if j < 0 {
				break
			}
			i += j + 4
			continue
		}
		if c := text[i]; c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		n := tokenLen(text[i:])
		tok := text[i : i+n]
		i += n
		if start < 0 && tok == ":" && len(toks) > 0 && toks[len(toks)-1] == "condition" {
			start = len(toks) + 1
		}
		toks = append(toks, tok)
	}
	end := -1
	for i, tok := range slices.Backward(toks) {
		if tok == "}" {
			end = i
			break
		}
	}
	if start < 0 || end < start {
		return nil, false
	}
	return toks[start:end], true
}

// tokenLen returns the length of the token s starts with, which is neither
// white space nor a comment.
func tokenLen(s string) int {
	c := s[0]
	if c == '"' || c == '/' {
		return literalLen(s)
	}
	if isWordByte(c) {
		n := 1
		for n < len(s) && isWordByte(s[n]) {
			n++
		}
		return n
	}
	if len(s) > 1 && s[1] == '=' && strings.IndexByte("=!<>", c) >= 0 {
		return 2
	}
	return 1
}

// literalLen returns the length of the string or regular expression that
// text starts with, through its closing delimiter.
func literalLen(text string) int {
	i := 1
	for i < len(text) && text[i] != text[0] {
		if text[i] == '\\' {
			i++
		}
		i++
	}
	return min(i+1, len(text))
}

// isWordByte reports whether c can be part of an identifier, keyword,
// number, or pattern reference such as $a or #a.
func isWordByte(c byte) bool {
	return c == '_' || c == '$' || c == '#' || c == '@' ||
		'0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// conjuncts returns the operands of the chain of "and" that toks, the
// tokens of a condition, form at the top level, or nil when "or" joins
// anything at the top level.
func conjuncts(toks []string) [][]string {
	toks = stripParens(toks)
	var out [][]string
	depth, last := 0, 0
	for i, tok := range toks {
		switch tok {
		case "(", "[":
			depth++
		case ")", "]":
			depth--
		}
		if depth != 0 {
			continue
		}
		if tok == "or" {
			return nil
		}
		if tok == "and" {
			out = append(out, toks[last:i])
			last = i + 1
		}
	}
	return append(out, toks[last:])
}

// stripParens returns toks without the parentheses that enclose all of it.
func stripParens(toks []string) []string {
	for len(toks) >= 2 && toks[0] == "(" && toks[len(toks)-1] == ")" && encloses(toks) {
		toks = toks[1 : len(toks)-1]
	}
	return toks
}

// encloses reports whether the parenthesis toks starts with stays open until
// its last token.
func encloses(toks []string) bool {
	depth := 0
	for _, tok := range toks[:len(toks)-1] {
		switch tok {
		case "(":
			depth++
		case ")":
			depth--
		}
		if depth == 0 {
			return false
		}
	}
	return true
}

// parsingRules reports for each rule whether it uses a module that parses
// files, directly or through the rules it refers to. A scoped rule set holding
// such a rule would parse each file it scans a second time.
func parsingRules(rules []splitRule) []bool {
	parses := make([]bool, len(rules))
	// Rules refer only to rules declared before them.
	for i, r := range rules {
		parses[i] = parsingModuleRE.MatchString(r.text) ||
			slices.ContainsFunc(r.refers, func(j int) bool { return parses[j] })
	}
	return parses
}

// overrideTargets returns the identifiers that override rules name.
func overrideTargets(files []splitFile) map[string]struct{} {
	out := map[string]struct{}{}
	for _, f := range files {
		for _, r := range f.rules {
			header := r.text
			if i := strings.IndexByte(header, '{'); i >= 0 {
				header = header[:i]
			}
			if !strings.Contains(header, "override") {
				continue
			}
			for _, m := range metaKeyRE.FindAllStringSubmatch(metaSection(r.text), -1) {
				if _, known := overrideKnownKeys[m[1]]; !known {
					out[m[1]] = struct{}{}
				}
			}
		}
	}
	return out
}

// metaSection returns the meta section of a rule's source.
func metaSection(text string) string {
	i := strings.Index(text, "meta:")
	if i < 0 {
		return ""
	}
	meta := text[i:]
	for _, next := range []string{"strings:", "condition:"} {
		if j := strings.Index(meta, next); j >= 0 {
			meta = meta[:j]
		}
	}
	return meta
}

// scopeMeta returns the scoping metadata a rule declares; when a key repeats,
// the last one counts, as in reports.
func scopeMeta(text string) map[string]string {
	out := map[string]string{}
	for _, m := range scopeKeyRE.FindAllStringSubmatch(metaSection(text), -1) {
		out[m[1]] = unquote(m[2])
	}
	return out
}

// unquote resolves the escapes YARA allows in a metadata string.
func unquote(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// CompileScoped compiles the scoped rules at the given indices of s.Scoped,
// with the rules they refer to, into a rule set. A split from
// RecursiveSplitCached keeps the sets it compiles in the cache, so that later
// runs load them instead.
func (s *Split) CompileScoped(ctx context.Context, indices []int) (*yarax.Rules, error) {
	name := s.scopedCacheName(indices)
	if name == "" {
		return s.compileSelected(ctx, indices)
	}
	cache, err := openCacheDir()
	if err != nil {
		return s.compileSelected(ctx, indices)
	}
	defer func() { _ = cache.Close() }()
	if rules, err := loadCachedRules(cache, name); err == nil {
		refreshCacheTime(cache, name, time.Now())
		return rules, nil
	}
	rules, err := s.compileSelected(ctx, indices)
	if err != nil {
		return nil, err
	}
	if err := saveCachedRules(cache, name, rules); err != nil {
		logWarn("Failed to save scoped rules to cache", "error", err)
	}
	return rules, nil
}

// scopedCacheName returns the name of the cache file of the scoped rules at
// indices, beside the split's own, or "" when the split is not cached.
func (s *Split) scopedCacheName(indices []int) string {
	if s.cacheName == "" {
		return ""
	}
	h := sha256.New()
	for _, i := range indices {
		_ = binary.Write(h, binary.LittleEndian, int64(i))
	}
	return strings.TrimSuffix(s.cacheName, cacheSuffix) + ".scoped-" + hex.EncodeToString(h.Sum(nil)) + cacheSuffix
}

// compileSelected compiles the scoped rules at indices, as CompileScoped does
// without the cache.
func (s *Split) compileSelected(ctx context.Context, indices []int) (*yarax.Rules, error) {
	want := make([]map[int]struct{}, len(s.files))
	for _, i := range indices {
		sr := s.Scoped[i]
		include(want, s.files, sr.file, sr.rule)
	}
	return compileFiles(ctx, s.files, func(fi, ri int) bool {
		_, ok := want[fi][ri]
		return ok
	})
}

// include adds rule ri of file fi, and every rule it refers to, to want.
func include(want []map[int]struct{}, files []splitFile, fi, ri int) {
	if want[fi] == nil {
		want[fi] = map[int]struct{}{}
	}
	if _, ok := want[fi][ri]; ok {
		return
	}
	want[fi][ri] = struct{}{}
	for _, dep := range files[fi].rules[ri].refers {
		include(want, files, fi, dep)
	}
}

// compileFiles compiles, in order, the rules of files that keep accepts, each
// file in its own namespace with the imports its kept rules use.
func compileFiles(ctx context.Context, files []splitFile, keep func(fi, ri int) bool) (*yarax.Rules, error) {
	yxc, err := newCompiler()
	if err != nil {
		return nil, err
	}
	var src bytes.Buffer
	for fi, f := range files {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		src.Reset()
		for ri, r := range f.rules {
			if keep(fi, ri) {
				src.WriteString(r.text)
			}
		}
		if src.Len() == 0 {
			continue
		}
		body := src.String()
		var head strings.Builder
		for _, imp := range f.imports {
			if strings.Contains(body, imp+".") {
				fmt.Fprintf(&head, "import %q\n", imp)
			}
		}
		yxc.NewNamespace(f.namespace)
		if err := yxc.AddSource(head.String()+body, yarax.WithOrigin(f.namespace)); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %v", f.namespace, err)
		}
	}
	if errs := yxc.Errors(); len(errs) > 0 {
		texts := make([]string, len(errs))
		for i, e := range errs {
			texts[i] = e.Text
		}
		return nil, fmt.Errorf("compile errors encountered: %v", texts)
	}
	return yxc.Build(), nil
}

// splitVersion names the layout of a Split's cache files. Change it whenever
// how rules are divided or what the manifest holds changes.
const splitVersion = "split3-"

// splitManifest is the part of a Split that the universal rules do not hold:
// the sources of the files with scoped rules, the scoped rules, the
// declaration order of every rule, and the rule sets by header.
type splitManifest struct {
	Files   []manifestFile
	Order   []RuleKey
	Scoped  []manifestScoped
	Headers []manifestHeader
}

// manifestHeader is the rule set for one header, serialized.
type manifestHeader struct {
	Header [2]byte
	Rules  []byte
}

type manifestFile struct {
	Namespace string
	Imports   []string
	Rules     []manifestRule
}

type manifestRule struct {
	Name   string
	Text   string
	Refers []int
	Scoped bool
}

type manifestScoped struct {
	Key  RuleKey
	Meta map[string]string
	File int
	Rule int
}

// manifest returns the manifest of s, holding only the files that contain
// scoped rules, which are all CompileScoped reads.
func (s *Split) manifest() (splitManifest, error) {
	m := splitManifest{Order: make([]RuleKey, len(s.Order))}
	for k, i := range s.Order {
		m.Order[i] = k
	}
	fileIndex := map[int]int{}
	for _, sr := range s.Scoped {
		fi, ok := fileIndex[sr.file]
		if !ok {
			f := s.files[sr.file]
			mf := manifestFile{Namespace: f.namespace, Imports: f.imports}
			for _, r := range f.rules {
				mf.Rules = append(mf.Rules, manifestRule{Name: r.name, Text: r.text, Refers: r.refers, Scoped: r.scoped})
			}
			fi = len(m.Files)
			fileIndex[sr.file] = fi
			m.Files = append(m.Files, mf)
		}
		m.Scoped = append(m.Scoped, manifestScoped{Key: sr.Key, Meta: sr.Meta, File: fi, Rule: sr.rule})
	}
	heads := slices.SortedFunc(maps.Keys(s.ByHeader), func(a, b [2]byte) int { return bytes.Compare(a[:], b[:]) })
	for _, head := range heads {
		rules, err := s.ByHeader[head].Load()
		if err != nil {
			return splitManifest{}, err
		}
		var buf bytes.Buffer
		if _, err := rules.WriteTo(&buf); err != nil {
			return splitManifest{}, fmt.Errorf("serialize rules for header %q: %w", head[:], err)
		}
		m.Headers = append(m.Headers, manifestHeader{Header: head, Rules: buf.Bytes()})
	}
	return m, nil
}

// splitFromManifest rebuilds a Split from its universal rules and manifest.
func splitFromManifest(universal *yarax.Rules, m splitManifest) (*Split, error) {
	s := &Split{Universal: universal, Order: make(map[RuleKey]int, len(m.Order)), ByHeader: make(map[[2]byte]*HeaderRules, len(m.Headers))}
	for i, k := range m.Order {
		s.Order[k] = i
	}
	for _, mh := range m.Headers {
		s.ByHeader[mh.Header] = &HeaderRules{data: mh.Rules}
	}
	for _, mf := range m.Files {
		f := splitFile{namespace: mf.Namespace, imports: mf.Imports}
		for _, r := range mf.Rules {
			for _, ref := range r.Refers {
				if ref < 0 || ref >= len(mf.Rules) {
					return nil, fmt.Errorf("manifest: rule %s refers outside its file", r.Name)
				}
			}
			f.rules = append(f.rules, splitRule{name: r.Name, text: r.Text, refers: r.Refers, scoped: r.Scoped})
		}
		s.files = append(s.files, f)
	}
	for _, ms := range m.Scoped {
		if ms.File < 0 || ms.File >= len(s.files) || ms.Rule < 0 || ms.Rule >= len(s.files[ms.File].rules) {
			return nil, fmt.Errorf("manifest: scoped rule %s out of range", ms.Key.Identifier)
		}
		s.Scoped = append(s.Scoped, ScopedRule{Key: ms.Key, Meta: ms.Meta, file: ms.File, rule: ms.Rule})
	}
	return s, nil
}

// RecursiveSplitCached is RecursiveSplit with the universal rules and the
// manifest cached on disk beside the cache RecursiveCached keeps.
func RecursiveSplitCached(ctx context.Context, fss []fs.FS) (*Split, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	cache, err := openCacheDir()
	if err != nil {
		return RecursiveSplit(ctx, fss)
	}
	defer func() { _ = cache.Close() }()
	key, err := getRulesHash(ctx, fss)
	if err != nil {
		return RecursiveSplit(ctx, fss)
	}

	cacheName := cachePrefix + splitVersion + key + cacheSuffix
	manifestName := cachePrefix + splitVersion + key + ".manifest" + cacheSuffix
	cacheFile := filepath.Join(cache.Name(), cacheName)
	if s, err := loadSplit(cache, cacheName, manifestName); err == nil {
		logDebug("Loaded split rules from cache", "file", cacheFile)
		now := time.Now()
		refreshCacheTime(cache, cacheName, now)
		refreshCacheTime(cache, manifestName, now)
		pruneStaleCaches(cache, cacheName, now)
		s.cacheName = cacheName
		return s, nil
	}

	logDebug("Cache miss, compiling split rules", "file", cacheFile)
	s, err := RecursiveSplit(ctx, fss)
	if err != nil {
		return nil, err
	}
	pruneStaleCaches(cache, cacheName, time.Now())
	if err := saveSplit(cache, s, cacheName, manifestName); err != nil {
		logWarn("Failed to save split rules to cache", "error", err)
		return s, nil
	}
	s.cacheName = cacheName
	return s, nil
}

// loadSplit loads a Split that saveSplit saved in cache.
func loadSplit(cache *os.Root, cacheName, manifestName string) (*Split, error) {
	data, err := loadVerified(cache, manifestName)
	if err != nil {
		return nil, err
	}
	var m splitManifest
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	universal, err := loadCachedRules(cache, cacheName)
	if err != nil {
		return nil, err
	}
	s, err := splitFromManifest(universal, m)
	if err != nil {
		universal.Destroy()
		return nil, err
	}
	return s, nil
}

// saveSplit writes the universal rules and the manifest of s to cache, each
// with its digest sidecar. The manifest is written last, so a partial save
// surfaces as a cache miss.
func saveSplit(cache *os.Root, s *Split, cacheName, manifestName string) error {
	if err := saveCachedRules(cache, cacheName, s.Universal); err != nil {
		return err
	}
	m, err := s.manifest()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(m); err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	return saveVerified(cache, manifestName, buf.Bytes())
}

// loadVerified reads name in cache and checks it against its digest sidecar.
func loadVerified(cache *os.Root, name string) ([]byte, error) {
	data, err := cache.ReadFile(name)
	if err != nil {
		return nil, err
	}
	want, err := readSidecarDigest(cache, name)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("digest mismatch for %s", filepath.Join(cache.Name(), name))
	}
	return data, nil
}

// saveVerified writes data to name in cache, with its digest sidecar,
// through temporary files renamed into place.
func saveVerified(cache *os.Root, name string, data []byte) error {
	f, tmp, err := file.CreateTemp(cache, ".rules-*.cache.tmp")
	if err != nil {
		return fmt.Errorf("create cache file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = cache.Remove(tmp)
		return fmt.Errorf("write cache file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = cache.Remove(tmp)
		return fmt.Errorf("close cache file: %w", err)
	}
	sum := sha256.Sum256(data)
	tmpSidecar, err := writeSidecarTemp(cache, hex.EncodeToString(sum[:]))
	if err != nil {
		_ = cache.Remove(tmp)
		return fmt.Errorf("write sidecar: %w", err)
	}
	if err := cache.Rename(tmp, name); err != nil {
		_ = cache.Remove(tmp)
		_ = cache.Remove(tmpSidecar)
		return fmt.Errorf("rename cache file: %w", err)
	}
	if err := cache.Rename(tmpSidecar, name+sidecarSuffix); err != nil {
		_ = cache.Remove(tmpSidecar)
		_ = cache.Remove(name)
		return fmt.Errorf("rename sidecar file: %w", err)
	}
	return nil
}
