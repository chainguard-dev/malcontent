// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/minio/sha256-simd"
	"golang.org/x/sync/errgroup"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/rules"

	yarax "github.com/VirusTotal/yara-x/go"
)

var FS = rules.FS

// badRules are noisy 3rd party rules to silently disable.
var badRules = map[string]struct{}{
	// YARAForge
	"GCTI_Sliver_Implant_32Bit":                           {},
	"GODMODERULES_IDDQD_God_Mode_Rule":                    {},
	"MALPEDIA_Win_Unidentified_107_Auto":                  {},
	"SIGNATURE_BASE_SUSP_PS1_JAB_Pattern_Jun22_1":         {},
	"ELCEEF_HTML_Smuggling_A":                             {},
	"DELIVRTO_SUSP_HTML_WASM_Smuggling":                   {},
	"SIGNATURE_BASE_FVEY_Shadowbroker_Auct_Dez16_Strings": {},
	"ELASTIC_Macos_Creddump_Keychainaccess_535C1511":      {},
	"SIGNATURE_BASE_Reconcommands_In_File":                {},
	"SIGNATURE_BASE_Apt_CN_Tetrisplugins_JS":              {},
	"CAPE_Sparkrat":                                       {},
	"SECUINFRA_SUSP_Powershell_Base64_Decode":             {},
	"SIGNATURE_BASE_SUSP_ELF_LNX_UPX_Compressed_File":     {},
	"DELIVRTO_SUSP_SVG_Foreignobject_Nov24":               {},
	"CAPE_Eternalromance":                                 {},
	"CAPE_Formhookb":                                      {},
	"TELEKOM_SECURITY_Cn_Utf8_Windows_Terminal":           {},
	"CAPE_Nitrogenloaderconfig":                           {},
	// ThreatHunting Keywords (some duplicates)
	"Adobe_XMP_Identifier":                       {},
	"Antivirus_Signature_signature_keyword":      {},
	"blackcat_ransomware_offensive_tool_keyword": {},
	"Dinjector_offensive_tool_keyword":           {},
	"empire_offensive_tool_keyword":              {},
	"github_greyware_tool_keyword":               {},
	"koadic_offensive_tool_keyword":              {},
	"mythic_offensive_tool_keyword":              {},
	"netcat_greyware_tool_keyword":               {},
	"nmap_greyware_tool_keyword":                 {},
	"portscan_offensive_tool_keyword":            {},
	"scp_greyware_tool_keyword":                  {},
	"sftp_greyware_tool_keyword":                 {},
	"ssh_greyware_tool_keyword":                  {},
	"usbpcap_offensive_tool_keyword":             {},
	"viperc2_offensive_tool_keyword":             {},
	"vsftpd_greyware_tool_keyword":               {},
	"wfuzz_offensive_tool_keyword":               {},
	"whoami_greyware_tool_keyword":               {},
	"wireshark_greyware_tool_keyword":            {},
	"mimikatz_offensive_tool_keyword":            {},
	// Inquest
	"Microsoft_Excel_Hidden_Macrosheet": {},
	"Adobe_Type_1_Font":                 {},
	// YARA VT
	"Base64_Encoded_URL":   {},
	"Windows_API_Function": {},
	// TTC-CERT
	"cve_202230190_html_payload": {},
	// JPCERT
	"malware_PlugX_config":   {},
	"malware_shellcode_hash": {},
	// bartblaze
	"Rclone":                        {},
	"Extract_MachineKey_SharePoint": {},
	// Rules that are incompatible with yara-x (unescaped braces in regex strings)
	"RTF_Header_Obfuscation":    {},
	"RTF_File_Malformed_Header": {},
}

// rulesWithWarnings determines what to do with rules that have known warnings: true=keep, false=disable.
var rulesWithWarnings = map[string]bool{
	"base64_str_replace":                    true,
	"DynastyPersist_offensive_tool_keyword": false,
	"gzinflate_str_replace":                 true,
	"hardcoded_ip_port":                     true,
	"hardcoded_ip":                          true,
	"Microsoft_Excel_with_Macrosheet":       false,
	"nmap_offensive_tool_keyword":           false,
	"opaque_binary":                         true,
	"PDF_with_Embedded_RTF_OLE_Newlines":    true,
	"php_short_concat_multiple":             true,
	"php_short_concat":                      true,
	"php_str_replace_obfuscation":           true,
	"Powershell_Case":                       true,
	"RDPassSpray_offensive_tool_keyword":    false,
	"rot13_str_replace":                     true,
	"sleep_and_background":                  true,
	"str_replace_obfuscation":               true,
	"systemd_no_comments_or_documentation":  true,
	"Agenda_golang":                         false,
	"bookworm_dll_UUID":                     false,
	"cobaltstrike_offensive_tool_keyword":   false,
	"amos_magic_var":                        true,
	"echo_decode_bash":                      true,
	"osascript_window_closer":               true,
	"osascript_quitter":                     true,
	"exfil_libcurl_elf":                     true,
	"small_opaque_archaic_gcc":              true,
	"bin_hardcoded_ip":                      true,
	"python_hex_decimal":                    true,
	"python_long_hex":                       true,
	"python_long_hex_multiple":              true,
	"pam_passwords":                         true,
	"decompress_base64_entropy":             true,
	"macho_opaque_binary":                   true,
	"macho_opaque_binary_long_str":          true,
	"long_str":                              true,
	"macho_backdoor_libc_signature":         true,
	"http_accept":                           true,
	"hardcoded_host_port":                   true,
	"hardcoded_host_port_over_10k":          true,
}

// rulePatternFormat matches a whole rule declaration; %s is the alternation
// of rule names to match.
const rulePatternFormat = `(?sm)^\s*rule\s+(%s)\s*(?::\s*[^\n{]+)?\s*{.*?^\s*}\s*$`

var newlinePattern = regexp.MustCompile(`\n{3,}`)

// getRulesToRemove returns the sorted names of the rules to remove from rule sources.
func getRulesToRemove() []string {
	rr := make([]string, 0, len(badRules)+len(rulesWithWarnings))
	for rule := range badRules {
		rr = append(rr, rule)
	}
	for rule, keep := range rulesWithWarnings {
		if !keep {
			rr = append(rr, rule)
		}
	}
	slices.Sort(rr)
	return rr
}

// ruleRemover deletes named rules from rule source text.
type ruleRemover struct {
	// declares matches the keyword and name that begin every match of rules.
	// It starts with a literal, so the regexp engine finds it by substring
	// search, while rules starts with ^\s* and must step through every byte.
	declares *regexp.Regexp
	rules    *regexp.Regexp
}

// newRuleRemover returns a remover for names, ignoring names that are not
// valid UTF-8. It returns nil, which removes nothing, when no names remain.
func newRuleRemover(names []string) *ruleRemover {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		if utf8.ValidString(name) {
			quoted = append(quoted, regexp.QuoteMeta(name))
		}
	}
	if len(quoted) == 0 {
		return nil
	}
	alternatives := strings.Join(quoted, "|")
	return &ruleRemover{
		declares: regexp.MustCompile(`rule\s+(?:` + alternatives + `)`),
		rules:    regexp.MustCompile(fmt.Sprintf(rulePatternFormat, alternatives)),
	}
}

// remove returns data without the named rules and with runs of three or more
// newlines collapsed to two. It may return data itself.
func (r *ruleRemover) remove(data []byte) []byte {
	if r == nil {
		return data
	}
	data = r.removeRuleMatches(data)
	// Every match of newlinePattern contains three newlines, so skipping the
	// replacement without them leaves the result unchanged.
	if bytes.Contains(data, []byte("\n\n\n")) {
		data = newlinePattern.ReplaceAll(data, []byte("\n\n"))
	}
	return data
}

// removeRuleMatches returns the same bytes as r.rules.ReplaceAll(data, nil)
// without running r.rules over all of data.
//
// A match of r.rules starts at a line start, continues through whitespace
// only, and then matches r.declares. So for each r.declares match, at kw, a
// match of r.rules through kw can only begin at ruleMatchStart, and runs of
// r.rules from there find exactly the matches ReplaceAll would, in order.
// Each search starts at or after the end of the previous one, so the work
// stays linear.
func (r *ruleRemover) removeRuleMatches(data []byte) []byte {
	var out []byte
	removed := false
	last, pos := 0, 0
	for pos < len(data) {
		loc := r.declares.FindIndex(data[pos:])
		if loc == nil {
			break
		}
		kw := pos + loc[0]
		start, ok := ruleMatchStart(data, last, kw)
		if !ok {
			pos = kw + 1
			continue
		}
		// start is a line start, so ^ holds at the front of data[start:]
		// exactly as it does in data.
		m := r.rules.FindIndex(data[start:])
		if m == nil {
			break
		}
		out = append(out, data[last:start+m[0]]...)
		removed = true
		last = start + m[1]
		pos = last
	}
	if !removed {
		return data
	}
	return append(out, data[last:]...)
}

// ruleMatchStart returns the earliest line start s, no earlier than last, for
// which data[s:kw] is all whitespace. A match of the rules pattern whose rule
// keyword sits at kw, found by a search that resumes at last, begins there.
// ok is false when no such line start exists.
func ruleMatchStart(data []byte, last, kw int) (s int, ok bool) {
	q := kw
	for q > last && isRegexpSpace(data[q-1]) {
		q--
	}
	if q == 0 || data[q-1] == '\n' {
		return q, true
	}
	if i := bytes.IndexByte(data[q:kw], '\n'); i >= 0 {
		return q + i + 1, true
	}
	return 0, false
}

// isRegexpSpace reports whether c is in the regexp class \s, [\t\n\f\r ].
func isRegexpSpace(c byte) bool {
	switch c {
	case '\t', '\n', '\f', '\r', ' ':
		return true
	}
	return false
}

// defaultRuleRemover drops the disabled rules. It is built on first use, so
// runs that load the compiled cache never compile its patterns.
var defaultRuleRemover = sync.OnceValue(func() *ruleRemover {
	return newRuleRemover(getRulesToRemove())
})

// isRuleFile reports whether path names a YARA rule source.
func isRuleFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".yara" || ext == ".yar"
}

// FileSHA256 names the global variable that holds the lowercase hex SHA-256
// digest of the scanned content. Scanners set it before every scan, so rules
// compare a file's digest without yara-x hashing the whole file again (the
// scan already computes it, with hardware acceleration).
const FileSHA256 = "file_sha256"

// newCompiler returns a compiler with the options every bundled rule set is
// built with.
func newCompiler() (*yarax.Compiler, error) {
	yxc, err := yarax.NewCompiler(
		yarax.ConditionOptimization(true),
		yarax.EnableIncludes(true),
		yarax.Globals(map[string]any{FileSHA256: ""}),
	)
	if err != nil {
		return nil, fmt.Errorf("yarax compiler: %w", err)
	}
	return yxc, nil
}

func Recursive(ctx context.Context, fss []fs.FS) (*yarax.Rules, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	yxc, err := newCompiler()
	if err != nil {
		return nil, err
	}

	remover := defaultRuleRemover()

	for _, root := range fss {
		err = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if ctx.Err() != nil {
				return ctx.Err()
			}

			if d.IsDir() {
				return nil
			}

			if isRuleFile(path) {
				bs, err := fs.ReadFile(root, path)
				if err != nil {
					return fmt.Errorf("readfile: %w", err)
				}

				bs = remover.remove(bs)

				yxc.NewNamespace(path)
				if err := yxc.AddSource(string(bs), yarax.WithOrigin(path)); err != nil {
					return fmt.Errorf("failed to parse %s: %v", path, err)
				}
			}

			return nil
		})
		if err != nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	compileErrs := yxc.Errors()
	errors := make([]string, 0, len(compileErrs))
	for _, yce := range compileErrs {
		clog.ErrorContext(ctx, "error", yce.Error())
		errors = append(errors, yce.Text)
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("compile errors encountered: %v", errors)
	}

	return yxc.Build(), nil
}

// getCacheDir returns the directory for storing compiled rules.
func getCacheDir() (string, error) {
	var cacheDir string

	if userCacheDir, err := os.UserCacheDir(); err == nil {
		cacheDir = filepath.Join(userCacheDir, "malcontent")
	} else {
		cacheDir = filepath.Join(os.TempDir(), "malcontent-cache")
	}

	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}

	// Verify the cache directory has safe permissions to prevent cache poisoning
	// via pre-created directories with permissive permissions
	fi, err := os.Stat(cacheDir)
	if err != nil {
		return "", fmt.Errorf("stat cache dir: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("cache directory %s has unsafe permissions %o (expected 0700)", cacheDir, fi.Mode().Perm())
	}

	sweepStaleTempFiles(cacheDir)

	return cacheDir, nil
}

const (
	// staleTempThreshold is the age past which an orphaned cache temp file is removed.
	staleTempThreshold = 24 * time.Hour

	// staleCacheThreshold is how long a compiled cache other than the current
	// one may go unmodified before it is removed. Several malcontent builds,
	// and runs with and without third-party rules, can share the cache
	// directory, so only caches that no run has refreshed for this long go.
	staleCacheThreshold = 72 * time.Hour
	// cacheTouchInterval is how stale a loaded cache's modification time may
	// get before loading refreshes it. A cache loaded within
	// staleCacheThreshold-cacheTouchInterval is therefore never pruned.
	cacheTouchInterval = 24 * time.Hour

	cachePrefix   = "rules-"
	cacheSuffix   = ".cache"
	sidecarSuffix = ".sha256"

	// cacheHashBufferSize is the read buffer for hashing a cache file.
	cacheHashBufferSize = 256 << 10
)

// sweepStaleTempFiles removes orphaned cache temp files left behind when a
// process is killed between os.CreateTemp and the atomic rename in saveCachedRules.
//
// It matches both the rules and sidecar temp suffixes (.rules-*.cache.tmp and
// .rules-*.sha256.tmp) via the shared .rules-*.tmp pattern, which never matches
// the live cache (rules-*.cache) or sidecar (rules-*.cache.sha256) files. The
// sweep is best-effort: errors are ignored and never block or fail compilation.
func sweepStaleTempFiles(cacheDir string) {
	matches, err := filepath.Glob(filepath.Join(cacheDir, ".rules-*.tmp"))
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-staleTempThreshold)
	for _, path := range matches {
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		if fi.ModTime().Before(cutoff) {
			_ = os.Remove(path)
		}
	}
}

// loadCachedRules loads rules saved by saveCachedRules and verifies them
// against the integrity sidecar.
//
// yarax.ReadFrom copies its whole input through io.ReadAll before it
// deserializes, so handing it a preloaded buffer would add a copy rather than
// save one. Instead a second reader hashes the same open file concurrently.
// Deserialization rebuilds the scanning engine and takes far longer than
// hashing, so the integrity check adds almost no wall time, and both readers
// see the same file even if the path is replaced meanwhile. Rules are returned
// only when the digest matches the sidecar; a mismatch or a missing sidecar is
// an error the caller treats as a cache miss.
func loadCachedRules(cacheFile string) (*yarax.Rules, error) {
	expected, err := readSidecarDigest(cacheFile)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(cacheFile) // #nosec G304 -- rule cache path derived from getRulesHash + cache dir permission gate
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	type digestResult struct {
		sum string
		err error
	}
	digest := make(chan digestResult, 1)
	go func() {
		h := sha256.New()
		_, err := io.CopyBuffer(h, io.NewSectionReader(f, 0, fi.Size()), make([]byte, cacheHashBufferSize))
		digest <- digestResult{sum: hex.EncodeToString(h.Sum(nil)), err: err}
	}()

	compiledRules, err := yarax.ReadFrom(io.NewSectionReader(f, 0, fi.Size()))
	got := <-digest
	if err != nil {
		return nil, fmt.Errorf("read cached rules: %w", err)
	}
	if got.err != nil {
		compiledRules.Destroy()
		return nil, fmt.Errorf("hash cached rules: %w", got.err)
	}
	if got.sum != expected {
		compiledRules.Destroy()
		return nil, fmt.Errorf("cache integrity mismatch: expected %s got %s", expected, got.sum)
	}
	return compiledRules, nil
}

// readSidecarDigest returns the expected digest recorded in the cache integrity sidecar.
func readSidecarDigest(cacheFile string) (string, error) {
	sidecarPath := cacheFile + sidecarSuffix
	expectedBytes, err := os.ReadFile(sidecarPath) // #nosec G304 -- sidecar path derived from cacheFile
	if err != nil {
		return "", fmt.Errorf("cache integrity sidecar missing: %w", err)
	}
	return strings.TrimSpace(string(expectedBytes)), nil
}

// saveCachedRules saves rules to a local file.
func saveCachedRules(compiledRules *yarax.Rules, cacheFile string) error {
	cacheDir := filepath.Dir(cacheFile)
	f, err := os.CreateTemp(cacheDir, ".rules-*.cache.tmp")
	if err != nil {
		return fmt.Errorf("create cache file: %w", err)
	}
	tmpFile := f.Name()

	// Hash the bytes as they are written rather than reading the file back.
	hasher := sha256.New()
	if _, err := compiledRules.WriteTo(io.MultiWriter(f, hasher)); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("write rules to cache: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("sync cache file: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("close cache file: %w", err)
	}

	tmpSidecar, err := writeSidecarTemp(cacheDir, hex.EncodeToString(hasher.Sum(nil)))
	if err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("write sidecar: %w", err)
	}

	// Rename cache before sidecar so a partial state surfaces as a cache miss in loadCachedRules.
	if err := os.Rename(tmpFile, cacheFile); err != nil {
		_ = os.Remove(tmpFile)
		_ = os.Remove(tmpSidecar)
		return fmt.Errorf("rename cache file: %w", err)
	}
	if err := os.Rename(tmpSidecar, cacheFile+sidecarSuffix); err != nil {
		_ = os.Remove(tmpSidecar)
		// Cache and sidecar must exist as an atomic pair; remove the orphaned cache file.
		_ = os.Remove(cacheFile)
		return fmt.Errorf("rename sidecar file: %w", err)
	}

	return nil
}

// writeSidecarTemp creates a temporary sidecar file in dir containing digest + newline and returns its path.
func writeSidecarTemp(dir, digest string) (string, error) {
	sf, err := os.CreateTemp(dir, ".rules-*.sha256.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := sf.Name()
	if _, err := sf.WriteString(digest + "\n"); err != nil {
		_ = sf.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := sf.Sync(); err != nil {
		_ = sf.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := sf.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

// getYaraXVersion returns the yara-x module version from build info.
// This is used to invalidate the cache when yara-x is updated.
func getYaraXVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/VirusTotal/yara-x/go" {
			return dep.Version
		}
	}
	return "unknown"
}

const (
	// cacheKeyVersion names the cache key layout. Change it whenever the
	// layout, the compiler options, or the source preprocessing in Recursive
	// changes, so caches built the old way are not reused.
	cacheKeyVersion = "malcontent-rules-v3"
	// hashChunkSize splits large rule files into pieces hashed in parallel;
	// a single third-party bundle holds most of the rule bytes.
	hashChunkSize = 256 << 10
	// hashBufferSize is each hashing worker's read buffer.
	hashBufferSize = 16 << 10
)

// ruleFile is a rule source found by walking a rule filesystem.
type ruleFile struct {
	fsys fs.FS
	path string
	size int64
}

// fileChunk is a piece of a rule file hashed on its own. file indexes the
// walk-ordered rule files, off is where the piece starts, and last marks the
// final piece, which reads to the end of the file.
type fileChunk struct {
	file int
	off  int64
	last bool
}

// getRulesHash returns the cache key for the rule sources in fss.
//
// The key is the SHA-256 of the key layout version, the yara-x version (its
// serialization format can change between releases), the names of the rules
// Recursive removes, and, for every rule file in walk order, its path, its
// size, and the SHA-256 of each of its hashChunkSize pieces. Variable-length
// fields carry their length, so no two inputs encode alike. Pieces are hashed
// concurrently but combined in walk order, so scheduling never changes the key.
func getRulesHash(ctx context.Context, fss []fs.FS) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	files, err := listRuleFiles(fss)
	if err != nil {
		return "", err
	}
	chunks := chunkRuleFiles(files)
	digests, err := hashChunks(ctx, files, chunks)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	rec := appendField(nil, cacheKeyVersion)
	rec = appendField(rec, getYaraXVersion())
	removed := getRulesToRemove()
	rec = binary.AppendVarint(rec, int64(len(removed)))
	for _, name := range removed {
		rec = appendField(rec, name)
	}
	h.Write(rec)

	for i, c := range chunks {
		rec = rec[:0]
		if c.off == 0 {
			rec = appendField(rec, files[c.file].path)
			rec = binary.AppendVarint(rec, files[c.file].size)
		}
		rec = append(rec, digests[i][:]...)
		h.Write(rec)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// appendField appends s to b behind its length so adjacent fields cannot run together.
func appendField(b []byte, s string) []byte {
	b = binary.AppendVarint(b, int64(len(s)))
	return append(b, s...)
}

// listRuleFiles returns the rule sources in fss in the order Recursive compiles them.
func listRuleFiles(fss []fs.FS) ([]ruleFile, error) {
	var files []ruleFile
	for _, fsys := range fss {
		err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !isRuleFile(path) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			files = append(files, ruleFile{fsys: fsys, path: path, size: info.Size()})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

// chunkRuleFiles splits each file into hashChunkSize pieces, in walk order.
// Every file, even an empty one, has exactly one piece at offset zero.
func chunkRuleFiles(files []ruleFile) []fileChunk {
	chunks := make([]fileChunk, 0, len(files))
	for i, f := range files {
		for off := int64(0); ; off += hashChunkSize {
			last := off+hashChunkSize >= f.size
			chunks = append(chunks, fileChunk{file: i, off: off, last: last})
			if last {
				break
			}
		}
	}
	return chunks
}

// hashChunks returns the SHA-256 of every chunk. Up to GOMAXPROCS workers
// claim chunks in turn, each reusing one hasher and one read buffer.
func hashChunks(ctx context.Context, files []ruleFile, chunks []fileChunk) ([][sha256.Size]byte, error) {
	digests := make([][sha256.Size]byte, len(chunks))
	var next atomic.Int64
	g, ctx := errgroup.WithContext(ctx)
	for range min(runtime.GOMAXPROCS(0), len(chunks)) {
		g.Go(func() error {
			h := sha256.New()
			buf := make([]byte, hashBufferSize)
			for i := next.Add(1) - 1; i < int64(len(chunks)); i = next.Add(1) - 1 {
				if err := ctx.Err(); err != nil {
					return err
				}
				c := chunks[i]
				if err := digestChunk(h, buf, files[c.file], c); err != nil {
					return err
				}
				// Sum appends into the slot's own 32-byte backing array.
				h.Sum(digests[i][:0])
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return digests, nil
}

// digestChunk resets h and feeds it chunk c of rf through buf. Streaming
// avoids fs.ReadFile, which copies each embedded file into a new allocation.
func digestChunk(h hash.Hash, buf []byte, rf ruleFile, c fileChunk) error {
	f, err := rf.fsys.Open(rf.path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if c.off > 0 {
		if err := seekTo(f, c.off); err != nil {
			return fmt.Errorf("seek %s: %w", rf.path, err)
		}
	}
	var r io.Reader = f
	if !c.last {
		r = &io.LimitedReader{R: f, N: hashChunkSize}
	}
	h.Reset()
	_, err = io.CopyBuffer(h, r, buf)
	return err
}

// seekTo moves f to off, reading forward when f cannot seek.
func seekTo(f fs.File, off int64) error {
	if s, ok := f.(io.Seeker); ok {
		_, err := s.Seek(off, io.SeekStart)
		return err
	}
	_, err := io.CopyN(io.Discard, f, off)
	return err
}

// refreshCacheTime marks cacheFile as in use so that other malcontent builds
// sharing the cache directory do not prune it. It rewrites the modification
// time at most once per cacheTouchInterval and ignores errors.
func refreshCacheTime(cacheFile string, now time.Time) {
	fi, err := os.Stat(cacheFile)
	if err != nil || now.Sub(fi.ModTime()) < cacheTouchInterval {
		return
	}
	_ = os.Chtimes(cacheFile, now, now)
}

// pruneStaleCaches removes compiled caches other than current, along with
// their integrity sidecars, once no run has refreshed them for
// staleCacheThreshold. It is best-effort: pruning only reclaims space, so
// errors are ignored. Temp files are left to sweepStaleTempFiles.
func pruneStaleCaches(cacheDir, current string, now time.Time) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}
	cutoff := now.Add(-staleCacheThreshold)
	keep := filepath.Base(current)
	for _, e := range entries {
		name := e.Name()
		cache, isSidecar := strings.CutSuffix(name, sidecarSuffix)
		if cache == keep || !isCacheName(cache) || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil || !fi.ModTime().Before(cutoff) {
			continue
		}
		// Loading refreshes only the cache's modification time, so a sidecar
		// stays as long as its cache is in use.
		if isSidecar && modifiedSince(filepath.Join(cacheDir, cache), cutoff) {
			continue
		}
		path := filepath.Join(cacheDir, name)
		if err := os.Remove(path); err == nil {
			logDebug("Removed stale rule cache", "file", path)
		}
	}
}

// isCacheName reports whether name has the form of a compiled cache file name.
func isCacheName(name string) bool {
	return strings.HasPrefix(name, cachePrefix) && strings.HasSuffix(name, cacheSuffix)
}

// modifiedSince reports whether path exists and was modified at or after t.
func modifiedSince(path string, t time.Time) bool {
	fi, err := os.Lstat(path)
	return err == nil && !fi.ModTime().Before(t)
}

// logDebug and logWarn emit the rule cache's log records through the default
// slog logger. They are variables so tests can record the messages without
// replacing the process-wide logger.
var (
	logDebug = slog.Debug
	logWarn  = slog.Warn
)

// RecursiveCached compiles rules with persistent disk caching to avoid penalizing successive executions with repeated rule compilations.
func RecursiveCached(ctx context.Context, fss []fs.FS) (*yarax.Rules, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	cacheDir, cacheErr := getCacheDir()
	if cacheErr != nil {
		return Recursive(ctx, fss)
	}

	key, hashErr := getRulesHash(ctx, fss)
	if hashErr != nil {
		return Recursive(ctx, fss)
	}

	cacheFile := filepath.Join(cacheDir, cachePrefix+key+cacheSuffix)
	if cachedRules, loadErr := loadCachedRules(cacheFile); loadErr == nil {
		logDebug("Loaded rules from cache", "file", cacheFile)
		now := time.Now()
		refreshCacheTime(cacheFile, now)
		pruneStaleCaches(cacheDir, cacheFile, now)
		return cachedRules, nil
	}

	logDebug("Cache miss, compiling rules", "file", cacheFile)
	compiledRules, err := Recursive(ctx, fss)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	// Prune first so space held by idle caches is free for the new one.
	pruneStaleCaches(cacheDir, cacheFile, time.Now())
	if saveErr := saveCachedRules(compiledRules, cacheFile); saveErr != nil {
		logWarn("Failed to save rules to cache", "error", saveErr)
	} else {
		logDebug("Saved rules to cache", "file", cacheFile)
	}

	return compiledRules, nil
}
