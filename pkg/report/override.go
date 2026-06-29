// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"strings"

	yarax "github.com/VirusTotal/yara-x/go"
)

// severityDrivenSources lists third-party rule sources, keyed by the second
// segment of their namespace (e.g. "guarddog" for yara/guarddog/...), whose
// rules express risk through a "severity" metadata key that matchRisk honors.
//
// This is deliberately an opt-in allowlist: other vendored sources (YARAForge,
// elastic, ...) also carry a "severity" meta for unrelated reasons, and their
// risk is intentionally derived from namespace reputation in behaviorRisk.
// Routing every severity-bearing rule through severityFromMeta would silently
// downgrade those curated signatures. Add a source here only once its severity
// metadata is meant to drive malcontent's risk score.
var severityDrivenSources = map[string]bool{
	"guarddog": true,
}

// isSeverityDriven reports whether a rule's namespace belongs to a source whose
// declared "severity" metadata should drive its risk score.
func isSeverityDriven(ns string) bool {
	return severityDrivenSources[nsSecondSegment(ns)]
}

// thirdPartyRiskOverrides re-weights individual severity-driven third-party
// rules so their self-declared severity lines up with malcontent's risk
// conventions for the equivalent behavior. It is keyed by YARA rule identifier
// and is the risk analog of compile.badRules / rulesWithWarnings: a focused,
// hand-maintained list intended to be edited as the upstream rule sets evolve.
//
// Severity-driven sources express risk through a "severity" metadata key (see
// severityFromMeta). Their broad, single-pattern heuristics often label a
// behavior "high" even though the generic form they match (e.g. "calls
// requests.get then exec()", "reads an env file", "spawns a scheduler") is
// malcontent's MEDIUM "notable" tier: it also occurs in legitimate code.
// malcontent reserves HIGH/CRITICAL for the specific, higher-confidence
// variants its own rules detect (hardcoded C2 hosts, mkfifo reverse shells,
// base64-decoded exec chains, and so on). Leaving these heuristics at HIGH
// makes a single match classify benign libraries as malicious.
//
// A rule absent from this map keeps the severity it declares in its own
// metadata (capability-style rules already classify themselves low/medium,
// matching malcontent's treatment of capabilities, so they need no entry here).
//
// Current entries are DataDog GuardDog (third_party/yara/guarddog) threat.*
// rules; add others here as additional severity-driven sources are folded in.
var thirdPartyRiskOverrides = map[string]int{
	// threat.* heuristics demoted high -> MEDIUM: broad behavioral matches that
	// recur in legitimate code. HIGH stays reserved for specific signatures.
	"threat_filesystem_autostart":              MEDIUM,
	"threat_filesystem_destruction":            MEDIUM,
	"threat_filesystem_read":                   MEDIUM,
	"threat_network_dns_exfil":                 MEDIUM,
	"threat_network_exfil_messenger":           MEDIUM,
	"threat_network_exfil_sysinfo":             MEDIUM,
	"threat_network_exfiltration":              MEDIUM,
	"threat_npm_dependency_confusion":          MEDIUM,
	"threat_npm_http_dependency":               MEDIUM,
	"threat_npm_preinstall_script":             MEDIUM,
	"threat_process_cryptomining":              MEDIUM,
	"threat_process_download_exec":             MEDIUM,
	"threat_process_injection_dll":             MEDIUM,
	"threat_process_memory":                    MEDIUM,
	"threat_process_powershell_encoded":        MEDIUM,
	"threat_runtime_dynamic_loader":            MEDIUM,
	"threat_runtime_keylogging":                MEDIUM,
	"threat_runtime_obfuscation_base64exec":    MEDIUM,
	"threat_runtime_obfuscation_chr":           MEDIUM,
	"threat_runtime_obfuscation_dynamic_eval":  MEDIUM,
	"threat_runtime_obfuscation_hidden_code":   MEDIUM,
	"threat_runtime_obfuscation_import_exec":   MEDIUM,
	"threat_runtime_obfuscation_steganography": MEDIUM,
	"threat_runtime_self_propagation":          MEDIUM,
	"threat_setup_import_aliasing":             MEDIUM,
	"threat_setup_network_in_install":          MEDIUM,
	"threat_setup_suspicious_imports":          MEDIUM,

	// threat_network_reverse_shell is intentionally left at its declared HIGH:
	// reverse-shell patterns are specific and malcontent classifies them HIGH
	// too. It is recorded here as documentation of a deliberate non-override.
	"threat_network_reverse_shell": HIGH,
}

// severityFromMeta returns the risk score encoded in a rule's "severity"
// metadata, if present. Severity-driven sources (e.g. GuardDog) express risk
// through a severity key (low/medium/high) rather than through malcontent tags;
// this lets us honor their classification instead of defaulting every match to
// the generic third-party risk.
func severityFromMeta(meta []yarax.Metadata) (int, bool) {
	for _, m := range meta {
		if m.Identifier() != "severity" {
			continue
		}
		if lvl, ok := Levels[strings.ToLower(fmt.Sprintf("%s", m.Value()))]; ok {
			return lvl, true
		}
	}
	return 0, false
}

// matchRisk returns the risk score for a matching rule. For severity-driven
// sources it prefers the rule's "severity" metadata (re-weighted by
// thirdPartyRiskOverrides where malcontent's conventions differ); every other
// rule is scored by namespace, name, and tags via behaviorRisk.
func matchRisk(m *yarax.Rule) int {
	if isSeverityDriven(m.Namespace()) {
		if sev, ok := severityFromMeta(m.Metadata()); ok {
			if override, ok := thirdPartyRiskOverrides[m.Identifier()]; ok {
				return override
			}
			return sev
		}
	}
	return behaviorRisk(m.Namespace(), m.Identifier(), m.Tags())
}
