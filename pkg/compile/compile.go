// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/rules"
	"github.com/hillu/go-yara/v4"
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
	// Rely on our first-party UPX rule
	"SIGNATURE_BASE_SUSP_ELF_LNX_UPX_Compressed_File": true,
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
	// YARA VT
	"Base64_Encoded_URL":   true,
	"Windows_API_Function": true,
	// TTC-CERT
	"cve_202230190_html_payload": true,
	// JPCERT
	"malware_PlugX_config":   true,
	"malware_shellcode_hash": true,
	// bartblaze
	"Rclone": true,
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

func Recursive(ctx context.Context, fss []fs.FS) (*yara.Rules, error) {
	logger := clog.FromContext(ctx)
	yc, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler: %w", err)
	}

	for _, root := range fss {
		err = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() && (filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar") {
				bs, err := fs.ReadFile(root, path)
				if err != nil {
					return fmt.Errorf("readfile: %w", err)
				}

				if err := yc.AddString(string(bs), path); err != nil {
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

	warnings := map[string]string{}
	for _, ycw := range yc.Warnings {
		clog.WarnContextf(ctx, "warning in %s line %d: %s", ycw.Filename, ycw.Line, ycw.Text)
		if ycw.Rule == "" {
			continue
		}
		parts := strings.Split(ycw.Rule, ".")
		id := parts[len(parts)-1]
		warnings[id] = ycw.Text
	}

	errors := []string{}
	for _, yce := range yc.Errors {
		logger.With("line", yce.Line, "filename", yce.Filename).Errorf("error: %s", yce.Text)
		if yce.Rule != "" {
			logger.With("rule", yce.Rule).Error("defective rule")
		}
		errors = append(errors, yce.Text)
	}
	if len(errors) > 0 {
		return nil, fmt.Errorf("compile errors encountered: %v", errors)
	}

	rs, err := yc.GetRules()
	if err != nil {
		return nil, err
	}
	for _, r := range rs.GetRules() {
		id := r.Identifier()
		if badRules[id] {
			r.Disable()
		}

		warning := warnings[id]
		if warning == "" {
			continue
		}

		// use rule name instead of filename to lower maintenance in the face of renames
		keep, known := rulesWithWarnings[id]
		if keep {
			continue
		}
		if !known {
			logger.With("namespace", r.Namespace(), "id", id).Errorf("disabled due to unexpected warning: %s", warnings[id])
		} else {
			logger.With("namespace", r.Namespace(), "id", id).Infof("disabled due to expected warning: %s", warnings[id])
		}
		r.Disable()
	}

	return rs, nil
}
