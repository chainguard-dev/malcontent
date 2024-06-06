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
	"GODMODERULES_IDDQD_God_Mode_Rule": true,
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
}

// rulesWithWarnings determines what to do with rules that have known warnings: true=keep, false=disable.
var rulesWithWarnings = map[string]bool{
	"opaque_binary":                         true,
	"hardcoded_ip":                          true,
	"hardcoded_ip_port":                     true,
	"systemd_no_comments_or_documentation":  true,
	"sleep_and_background":                  true,
	"RDPassSpray_offensive_tool_keyword":    false,
	"nmap_offensive_tool_keyword":           false,
	"DynastyPersist_offensive_tool_keyword": false,
}

func Recursive(ctx context.Context, fss []fs.FS) (*yara.Rules, error) {
	yc, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler: %w", err)
	}

	addErrs := []error{}
	for _, root := range fss {
		err = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			logger := clog.FromContext(ctx).With("path", path)
			if !d.IsDir() && (filepath.Ext(path) == ".yara" || filepath.Ext(path) == ".yar") {
				bs, err := fs.ReadFile(root, path)
				if err != nil {
					return fmt.Errorf("readfile: %w", err)
				}

				// Our Yara library panics a lot
				defer func() {
					if err := recover(); err != nil {
						logger.Error("recovered from panic", slog.Any("error", err))
					}
				}()

				if err := yc.AddString(string(bs), path); err != nil {
					err = fmt.Errorf("yara addfile %s: %w", path, err)
					addErrs = append(addErrs, err)
					return err
				}
			}

			return nil
		})
	}

	if len(addErrs) > 0 {
		// Normally I would use errors.Join, but only the first error is useful in go-yara
		return nil, addErrs[0]
	}

	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}

	warnings := map[string]string{}
	for _, ycw := range yc.Warnings {
		clog.WarnContext(ctx, "warning", slog.String("namespace", ycw.Rule.Namespace()), slog.String("warning", ycw.Text), slog.String("id", ycw.Rule.Identifier()))
		id := fmt.Sprintf("%s:%s", ycw.Rule.Namespace(), ycw.Rule.Identifier())
		warnings[id] = ycw.Text
	}

	for _, yce := range yc.Errors {
		clog.ErrorContext(ctx, "errors", slog.String("namespace", yce.Rule.Namespace()), slog.String("error", yce.Text), slog.String("id", yce.Rule.Identifier()))
		return nil, fmt.Errorf("rule error: %v", yce.Text)
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
