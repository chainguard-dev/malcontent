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

// hardenedConfigFlags returns the subset of the global flag set that exposes the
// hardened configuration fields: the archive caps, the extractor-panic switch,
// and the OCI transport knobs. Each flag mirrors the production definition in
// mal.go exactly (name, default Value, and the package-level Destination pointer)
// so that parsing through urfave/cli populates the same variables the real Before
// hook reads.
func hardenedConfigFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "exit-on-extractor-panic",
			Value:       false,
			Destination: &exitExtractorPanicFlag,
		},
		&cli.Int64Flag{
			Name:        "max-archive-bytes",
			Value:       file.DefaultMaxArchiveBytes,
			Destination: &maxArchiveBytesFlag,
		},
		&cli.FloatFlag{
			Name:        "max-archive-ratio",
			Value:       file.DefaultMaxArchiveRatio,
			Destination: &maxArchiveRatioFlag,
		},
		&cli.IntFlag{
			Name:        "oci-pull-timeout-seconds",
			Value:       600,
			Destination: &ociPullTimeoutFlag,
		},
		&cli.IntFlag{
			Name:        "oci-retry-max-attempts",
			Value:       3,
			Destination: &ociRetryMaxAttemptsFlag,
		},
		&cli.IntFlag{
			Name:        "oci-retry-max-window-seconds",
			Value:       60,
			Destination: &ociRetryMaxWindowFlag,
		},
		&cli.IntFlag{
			Name:        "oci-per-host-slots",
			Value:       4,
			Destination: &ociPerHostSlotsFlag,
		},
		&cli.StringFlag{
			Name:        "oci-keepalive-policy",
			Value:       string(malcontent.KeepalivePolicyExplicitlyEnabled),
			Destination: &ociKeepalivePolicyFlag,
		},
		&cli.IntFlag{
			Name:        "oci-keepalive-seconds",
			Value:       30,
			Destination: &ociKeepaliveSecondsFlag,
		},
		&cli.BoolFlag{
			Name:        "oci-proxy-opt-in",
			Value:       false,
			Destination: &ociProxyOptInFlag,
		},
	}
}

// configFromFlags lands the parsed flag variables into a malcontent.Config using
// the same field assignments mal.go's Before hook performs. Keeping this in step
// with mal.go is the contract the wiring test guards.
func configFromFlags() malcontent.Config {
	return malcontent.Config{
		ExitOnExtractorPanic:     exitExtractorPanicFlag,
		MaxArchiveBytes:          maxArchiveBytesFlag,
		MaxArchiveRatio:          maxArchiveRatioFlag,
		OCICABundlePath:          caBundleFlag,
		OCIKeepalivePolicy:       malcontent.KeepalivePolicy(ociKeepalivePolicyFlag),
		OCIKeepaliveSeconds:      ociKeepaliveSecondsFlag,
		OCIPerHostSlots:          ociPerHostSlotsFlag,
		OCIProxyOptIn:            ociProxyOptInFlag,
		OCIPullTimeoutSeconds:    ociPullTimeoutFlag,
		OCIRetryMaxAttempts:      ociRetryMaxAttemptsFlag,
		OCIRetryMaxWindowSeconds: ociRetryMaxWindowFlag,
	}
}

// parseGlobals drives urfave/cli over the hardened config flags so that the real
// Destination wiring populates the package-level flag variables, then returns
// the resulting Config. The Action is a no-op terminal so no scan (and no
// CGO/YARA work) runs; only flag parsing is exercised.
func parseGlobals(t *testing.T, args []string) malcontent.Config {
	t.Helper()

	caBundleFlag = "system"

	cmd := &cli.Command{
		Name:  "mal",
		Flags: hardenedConfigFlags(),
		Commands: []*cli.Command{
			{
				Name: "scan",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "ca-bundle",
						Value:       "system",
						Destination: &caBundleFlag,
					},
				},
				Action: func(_ context.Context, _ *cli.Command) error { return nil },
			},
		},
	}

	if err := cmd.Run(context.Background(), args); err != nil {
		t.Fatalf("cmd.Run(%v): unexpected error: %v", args, err)
	}

	return configFromFlags()
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
