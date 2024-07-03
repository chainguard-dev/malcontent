// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"

	"github.com/chainguard-dev/bincapz/rules"
	"github.com/chainguard-dev/clog"
	"github.com/hillu/go-yara/v4"
)

var FS = rules.FS

// badRules are noisy 3rd party rules to silently disable.
var badRules = map[string]bool{
	// YARAForge
	"GODMODERULES_IDDQD_God_Mode_Rule":   true,
	"MALPEDIA_Win_Unidentified_107_Auto": true,
	// ThreatHunting Keywords (some duplicates)
	"scp_greyware_tool_keyword":                  true,
	"Antivirus_Signature_signature_keyword":      true,
	"Dinjector_offensive_tool_keyword":           true,
	"viperc2_offensive_tool_keyword":             true,
	"github_greyware_tool_keyword":               true,
	"wfuzz_offensive_tool_keyword":               true,
	"nmap_greyware_tool_keyword":                 true,
	"netcat_greyware_tool_keyword":               true,
	"whoami_greyware_tool_keyword":               true,
	"sftp_greyware_tool_keyword":                 true,
	"empire_offensive_tool_keyword":              true,
	"ssh_greyware_tool_keyword":                  true,
	"wireshark_greyware_tool_keyword":            true,
	"portscan_offensive_tool_keyword":            true,
	"usbpcap_offensive_tool_keyword":             true,
	"koadic_offensive_tool_keyword":              true,
	"vsftpd_greyware_tool_keyword":               true,
	"blackcat_ransomware_offensive_tool_keyword": true,
	"mythic_offensive_tool_keyword":              true,
	"Adobe_XMP_Identifier":                       true,
	// YARA VT
	"Windows_API_Function": true,
	"Base64_Encoded_URL":   true,
}

// rulesWithWarnings determines what to do with rules that have known warnings: true=keep, false=disable.
var rulesWithWarnings = map[string]bool{
	"opaque_binary":                         true,
	"hardcoded_ip":                          true,
	"str_replace_obfuscation":               true,
	"rot13_str_replace":                     true,
	"gzinflate_str_replace":                 true,
	"php_str_replace_obfuscation":           true,
	"hardcoded_ip_port":                     true,
	"base64_str_replace":                    true,
	"systemd_no_comments_or_documentation":  true,
	"sleep_and_background":                  true,
	"Microsoft_Excel_with_Macrosheet":       true,
	"PDF_with_Embedded_RTF_OLE_Newlines":    true,
	"Powershell_Case":                       true,
	"RDPassSpray_offensive_tool_keyword":    false,
	"nmap_offensive_tool_keyword":           false,
	"DynastyPersist_offensive_tool_keyword": false,
}

func Recursive(ctx context.Context, fss []fs.FS) (*yara.Rules, error) {
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
		clog.WarnContext(ctx, "warning", slog.String("filename", ycw.Filename), slog.Int("line", ycw.Line), slog.String("text", ycw.Text))
		if ycw.Rule == nil {
			continue
		}

		id := fmt.Sprintf("%s:%s", ycw.Rule.Namespace(), ycw.Rule.Identifier())
		clog.WarnContext(ctx, "rule has warning", "id", id)
		warnings[id] = ycw.Text
	}

	errors := []string{}
	for _, yce := range yc.Errors {
		clog.ErrorContext(ctx, "error", slog.String("filename", yce.Filename), slog.Int("line", yce.Line), slog.String("text", yce.Text))
		if yce.Rule != nil {
			clog.ErrorContext(ctx, "defective rule", slog.String("namespace", yce.Rule.Namespace()), slog.String("id", yce.Rule.Identifier()))
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
		if badRules[r.Identifier()] {
			clog.InfoContext(ctx, "info", slog.String("namespace", r.Namespace()), slog.String("id", r.Identifier()), slog.String("reason", "disabled (known bad rule)"))
			r.Disable()
		}

		id := fmt.Sprintf("%s:%s", r.Namespace(), r.Identifier())
		warning := warnings[id]
		if warning == "" {
			continue
		}

		// use rule name instead of filename to lower maintenance in the face of renames
		keep, known := rulesWithWarnings[r.Identifier()]
		if keep {
			continue
		}
		if !known {
			clog.ErrorContext(ctx, "error", slog.String("namespace", r.Namespace()), slog.String("id", r.Identifier()), slog.String("disabled due to unexpected warning", warnings[id]))
		} else {
			clog.InfoContext(ctx, "info", slog.String("namespace", r.Namespace()), slog.String("id", r.Identifier()), slog.String("disabled due to expected warning", warnings[id]))
		}
		r.Disable()
	}

	return rs, nil
}
