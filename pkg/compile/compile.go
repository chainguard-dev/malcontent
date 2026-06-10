// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/minio/sha256-simd"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/rules"

	yarax "github.com/VirusTotal/yara-x/go"
)

var FS = rules.FS

// badRules are noisy 3rd party rules to silently disable.
var badRules = map[string]bool{
	// YARAForge
	"GCTI_Sliver_Implant_32Bit":                           true,
	"GODMODERULES_IDDQD_God_Mode_Rule":                    true,
	"MALPEDIA_Win_Unidentified_107_Auto":                  true,
	"SIGNATURE_BASE_SUSP_PS1_JAB_Pattern_Jun22_1":         true,
	"ELCEEF_HTML_Smuggling_A":                             true,
	"DELIVRTO_SUSP_HTML_WASM_Smuggling":                   true,
	"SIGNATURE_BASE_FVEY_Shadowbroker_Auct_Dez16_Strings": true,
	"ELASTIC_Macos_Creddump_Keychainaccess_535C1511":      true,
	"SIGNATURE_BASE_Reconcommands_In_File":                true,
	"SIGNATURE_BASE_Apt_CN_Tetrisplugins_JS":              true,
	"CAPE_Sparkrat":                                       true,
	"SECUINFRA_SUSP_Powershell_Base64_Decode":             true,
	"SIGNATURE_BASE_SUSP_ELF_LNX_UPX_Compressed_File":     true,
	"DELIVRTO_SUSP_SVG_Foreignobject_Nov24":               true,
	"CAPE_Eternalromance":                                 true,
	"CAPE_Formhookb":                                      true,
	"TELEKOM_SECURITY_Cn_Utf8_Windows_Terminal":           true,
	"CAPE_Nitrogenloaderconfig":                           true,
	// ThreatHunting Keywords (some duplicates)
	"Adobe_XMP_Identifier":                       true,
	"Antivirus_Signature_signature_keyword":      true,
	"blackcat_ransomware_offensive_tool_keyword": true,
	"Dinjector_offensive_tool_keyword":           true,
	"empire_offensive_tool_keyword":              true,
	"github_greyware_tool_keyword":               true,
	"koadic_offensive_tool_keyword":              true,
	"mythic_offensive_tool_keyword":              true,
	"netcat_greyware_tool_keyword":               true,
	"nmap_greyware_tool_keyword":                 true,
	"portscan_offensive_tool_keyword":            true,
	"scp_greyware_tool_keyword":                  true,
	"sftp_greyware_tool_keyword":                 true,
	"ssh_greyware_tool_keyword":                  true,
	"usbpcap_offensive_tool_keyword":             true,
	"viperc2_offensive_tool_keyword":             true,
	"vsftpd_greyware_tool_keyword":               true,
	"wfuzz_offensive_tool_keyword":               true,
	"whoami_greyware_tool_keyword":               true,
	"wireshark_greyware_tool_keyword":            true,
	"mimikatz_offensive_tool_keyword":            true,
	// Inquest
	"Microsoft_Excel_Hidden_Macrosheet": true,
	"Adobe_Type_1_Font":                 true,
	// YARA VT
	"Base64_Encoded_URL":   true,
	"Windows_API_Function": true,
	// TTC-CERT
	"cve_202230190_html_payload": true,
	// JPCERT
	"malware_PlugX_config":   true,
	"malware_shellcode_hash": true,
	// bartblaze
	"Rclone":                        true,
	"Extract_MachineKey_SharePoint": true,
	// Rules that are incompatible with yara-x (unescaped braces in regex strings)
	"RTF_Header_Obfuscation":    true,
	"RTF_File_Malformed_Header": true,
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

var (
	rulePattern    = regexp.MustCompile(`(?sm)^\s*rule\s+(%s)\s*(?::\s*[^\n{]+)?\s*{.*?^\s*}\s*$`)
	newlinePattern = regexp.MustCompile(`\n{3,}`)
)

// getRulesToRemove returns a consolidated list of rules to remove from a rule string.
func getRulesToRemove() []string {
	rr := make([]string, 0)
	// Add rules from badRules map that are marked true
	for rule, remove := range badRules {
		if remove {
			rr = append(rr, rule)
		}
	}
	// Add rules from rulesWithWarnings map that are marked false
	for rule, keep := range rulesWithWarnings {
		if !keep {
			rr = append(rr, rule)
		}
	}
	return rr
}

// removeRules removes rule matches from the file data.
func removeRules(data []byte, rulesToRemove []string) []byte {
	if len(rulesToRemove) == 0 {
		return data
	}

	modified := data
	ruleNames := make([]string, len(rulesToRemove))
	for i, name := range rulesToRemove {
		// we only ever include rules listed above in badRules and rulesWithWarnings
		// but ignore any rule names that aren't valid UTF-8
		if !utf8.ValidString(name) {
			continue
		}
		ruleNames[i] = regexp.QuoteMeta(name)
	}
	pattern := regexp.MustCompile(fmt.Sprintf(
		rulePattern.String(),
		strings.Join(ruleNames, "|"),
	))
	modified = pattern.ReplaceAll(modified, []byte{})
	return newlinePattern.ReplaceAll(modified, []byte("\n\n"))
}

func Recursive(ctx context.Context, fss []fs.FS) (*yarax.Rules, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	yxc, err := yarax.NewCompiler(yarax.ConditionOptimization(true), yarax.EnableIncludes(true))
	if err != nil {
		return nil, fmt.Errorf("yarax compiler: %w", err)
	}

	rulesToRemove := getRulesToRemove()

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

			if filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar" {
				bs, err := fs.ReadFile(root, path)
				if err != nil {
					return fmt.Errorf("readfile: %w", err)
				}

				bs = removeRules(bs, rulesToRemove)

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

	errors := []string{}
	for _, yce := range yxc.Errors() {
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

// staleTempThreshold is the age past which an orphaned cache temp file is removed.
const staleTempThreshold = 24 * time.Hour

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

// loadCachedRules attempts to load rules from the local, compiled rules.
//
// The cache file is read in a single pass: a TeeReader feeds the same bytes to
// the yara-x deserializer and to the SHA-256 hasher. The digest is compared
// against the integrity sidecar after deserialization, and rules are returned
// only when the digest matches the sidecar. A mismatch (or a missing sidecar)
// surfaces as an error so the caller treats it as a cache miss and recompiles.
//
// Caches written before the sidecar landed will fail this integrity check and recompute.
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

	hasher := sha256.New()
	compiledRules, err := yarax.ReadFrom(io.TeeReader(f, hasher))
	if err != nil {
		return nil, fmt.Errorf("read cached rules: %w", err)
	}

	actual := fmt.Sprintf("%x", hasher.Sum(nil))
	if actual != expected {
		return nil, fmt.Errorf("cache integrity mismatch: expected %s got %s", expected, actual)
	}

	return compiledRules, nil
}

// readSidecarDigest returns the expected digest recorded in the cache integrity sidecar.
func readSidecarDigest(cacheFile string) (string, error) {
	sidecarPath := cacheFile + ".sha256"
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

	if _, err := compiledRules.WriteTo(f); err != nil {
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

	digest, err := hashFile(tmpFile)
	if err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("hash cache file: %w", err)
	}

	tmpSidecar, err := writeSidecarTemp(cacheDir, digest)
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
	if err := os.Rename(tmpSidecar, cacheFile+".sha256"); err != nil {
		_ = os.Remove(tmpSidecar)
		// Cache and sidecar must exist as an atomic pair; remove the orphaned cache file.
		_ = os.Remove(cacheFile)
		return fmt.Errorf("rename sidecar file: %w", err)
	}

	return nil
}

// hashFile returns the lowercase hex sha256 digest of a file's contents.
func hashFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path supplied by saveCachedRules from CreateTemp
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
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

// getRulesHash computes a hash of the rule sources for cache validation.
// It includes the yara-x version to ensure cache invalidation when
// yara-x is updated with incompatible serialization format changes.
func getRulesHash(ctx context.Context, fss []fs.FS) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	hasher := sha256.New()

	// Include yara-x version in hash to invalidate cache on version changes
	hasher.Write([]byte(getYaraXVersion()))

	for _, fsys := range fss {
		err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar" {
				hasher.Write([]byte(path))
				content, err := fs.ReadFile(fsys, path)
				if err != nil {
					return err
				}
				hasher.Write(content)
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// RecursiveCached compiles rules with persistent disk caching to avoid penalizing successive executions with repeated rule compilations.
func RecursiveCached(ctx context.Context, fss []fs.FS) (*yarax.Rules, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	cacheDir, cacheErr := getCacheDir()
	if cacheErr != nil {
		return Recursive(ctx, fss)
	}

	hash, hashErr := getRulesHash(ctx, fss)
	if hashErr != nil {
		return Recursive(ctx, fss)
	}

	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("rules-%s.cache", hash))
	if cachedRules, loadErr := loadCachedRules(cacheFile); loadErr == nil {
		slog.Debug("Loaded rules from cache", "file", cacheFile)
		return cachedRules, nil
	}

	slog.Debug("Cache miss, compiling rules", "file", cacheFile)
	compiledRules, err := Recursive(ctx, fss)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	if saveErr := saveCachedRules(compiledRules, cacheFile); saveErr != nil {
		slog.Warn("Failed to save rules to cache", "error", saveErr)
	} else {
		slog.Debug("Saved rules to cache", "file", cacheFile)
	}

	return compiledRules, nil
}
