// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
	modified := data
	ruleNames := make([]string, len(rulesToRemove))
	for i, name := range rulesToRemove {
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

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}

	return cacheDir, nil
}

// loadCachedRules attempts to load rules from the local, compiled rules.
func loadCachedRules(cacheFile string) (*yarax.Rules, error) {
	file, err := os.Open(cacheFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	compiledRules, err := yarax.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("read cached rules: %w", err)
	}

	return compiledRules, nil
}

// saveCachedRules saves rules to a local file.
func saveCachedRules(compiledRules *yarax.Rules, cacheFile string) error {
	tmpFile := cacheFile + ".tmp"
	file, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create cache file: %w", err)
	}
	defer file.Close()

	if _, err := compiledRules.WriteTo(file); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("write rules to cache: %w", err)
	}

	if err := os.Rename(tmpFile, cacheFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("rename cache file: %w", err)
	}

	return nil
}

// getRulesHash computes a hash of the rule sources for cache validation.
func getRulesHash(ctx context.Context, fss []fs.FS) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	hasher := sha256.New()

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
