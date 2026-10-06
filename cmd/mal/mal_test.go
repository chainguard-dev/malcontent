// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/urfave/cli/v3"
)

// parseFlags drives urfave/cli over the production global flags so that
// their Destination wiring populates the package-level flag variables. Every
// flag not named in args is reset to its default. The scan Action is a no-op,
// so no rules are compiled and nothing is scanned.
func parseFlags(t *testing.T, args []string) {
	t.Helper()

	cmd := &cli.Command{
		Name:  "mal",
		Flags: globalFlags(),
		Commands: []*cli.Command{
			{
				Name:   "scan",
				Flags:  targetFlags(),
				Action: func(_ context.Context, _ *cli.Command) error { return nil },
			},
		},
	}

	if err := cmd.Run(t.Context(), args); err != nil {
		t.Fatalf("cmd.Run(%v): unexpected error: %v", args, err)
	}
}

// parseGlobals parses args with parseFlags and returns the Config that
// configFromFlags assembles from the resulting flag variables.
func parseGlobals(t *testing.T, args []string) malcontent.Config {
	t.Helper()

	parseFlags(t, args)
	cfg, err := configFromFlags()
	if err != nil {
		t.Fatalf("configFromFlags() after %v: unexpected error: %v", args, err)
	}
	return cfg
}

func TestGlobalFlagDefaults(t *testing.T) {
	cfg := parseGlobals(t, []string{"mal", "scan"})

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"exit-on-extractor-panic", cfg.ExitOnExtractorPanic, false},
		{"max-archive-bytes", cfg.MaxArchiveBytes, file.DefaultMaxArchiveBytes},
		{"max-archive-ratio", cfg.MaxArchiveRatio, file.DefaultMaxArchiveRatio},
		{"ca-bundle", cfg.OCICABundlePath, "system"},
		{"oci-pull-timeout-seconds", cfg.OCIPullTimeoutSeconds, 600},
		{"oci-retry-max-attempts", cfg.OCIRetryMaxAttempts, 3},
		{"oci-retry-max-window-seconds", cfg.OCIRetryMaxWindowSeconds, 60},
		{"oci-per-host-slots", cfg.OCIPerHostSlots, 4},
		{"oci-keepalive-policy", cfg.OCIKeepalivePolicy, malcontent.KeepalivePolicyExplicitlyEnabled},
		{"oci-keepalive-seconds", cfg.OCIKeepaliveSeconds, 30},
		{"oci-proxy-opt-in", cfg.OCIProxyOptIn, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("default for %s: got %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestGlobalFlagWiring(t *testing.T) {
	args := []string{
		"mal",
		"--exit-on-extractor-panic",
		"--max-archive-bytes", "1024",
		"--max-archive-ratio", "12.5",
		"--oci-pull-timeout-seconds", "111",
		"--oci-retry-max-attempts", "7",
		"--oci-retry-max-window-seconds", "222",
		"--oci-per-host-slots", "9",
		"--oci-keepalive-policy", "disabled",
		"--oci-keepalive-seconds", "45",
		"--oci-proxy-opt-in",
		"scan",
		"--ca-bundle", "/etc/ssl/custom.pem",
	}

	cfg := parseGlobals(t, args)

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"exit-on-extractor-panic", cfg.ExitOnExtractorPanic, true},
		{"max-archive-bytes", cfg.MaxArchiveBytes, int64(1024)},
		{"max-archive-ratio", cfg.MaxArchiveRatio, 12.5},
		{"ca-bundle", cfg.OCICABundlePath, "/etc/ssl/custom.pem"},
		{"oci-pull-timeout-seconds", cfg.OCIPullTimeoutSeconds, 111},
		{"oci-retry-max-attempts", cfg.OCIRetryMaxAttempts, 7},
		{"oci-retry-max-window-seconds", cfg.OCIRetryMaxWindowSeconds, 222},
		{"oci-per-host-slots", cfg.OCIPerHostSlots, 9},
		{"oci-keepalive-policy", cfg.OCIKeepalivePolicy, malcontent.KeepalivePolicyExplicitlyDisabled},
		{"oci-keepalive-seconds", cfg.OCIKeepaliveSeconds, 45},
		{"oci-proxy-opt-in", cfg.OCIProxyOptIn, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("wiring for %s: got %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}
