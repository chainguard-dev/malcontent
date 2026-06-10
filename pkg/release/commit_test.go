// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"testing"
)

func TestIsFortyHexLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "valid lowercase hex", in: "0123456789abcdef0123456789abcdef01234567", want: true},
		{name: "all f", in: "ffffffffffffffffffffffffffffffffffffffff", want: true},
		{name: "empty", in: "", want: false},
		{name: "main literal", in: "main", want: false},
		{name: "thirty-nine chars", in: "0123456789abcdef0123456789abcdef0123456", want: false},
		{name: "forty-one chars", in: "0123456789abcdef0123456789abcdef012345678", want: false},
		{name: "uppercase rejected", in: "0123456789ABCDEF0123456789ABCDEF01234567", want: false},
		{name: "non-hex char g", in: "g123456789abcdef0123456789abcdef01234567", want: false},
		{name: "non-hex char z", in: "z123456789abcdef0123456789abcdef01234567", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isFortyHexLower(tc.in); got != tc.want {
				t.Errorf("isFortyHexLower(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestResolveRuleURLCommit(t *testing.T) {
	tests := []struct {
		name        string
		buildCommit string
		want        string
	}{
		{
			name:        "valid 40-hex BuildCommit returned",
			buildCommit: "fedcba9876543210fedcba9876543210fedcba98",
			want:        "fedcba9876543210fedcba9876543210fedcba98",
		},
		{
			name:        "empty BuildCommit returns empty",
			buildCommit: "",
			want:        "",
		},
		{
			name:        "non-hex BuildCommit returns empty",
			buildCommit: "not-a-sha",
			want:        "",
		},
		{
			name:        "short hex returns empty",
			buildCommit: "abcdef01",
			want:        "",
		},
		{
			name:        "uppercase hex rejected",
			buildCommit: "FEDCBA9876543210FEDCBA9876543210FEDCBA98",
			want:        "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// not parallel: mutates package global
			original := BuildCommit
			t.Cleanup(func() {
				BuildCommit = original
				ResetRuleURLRef()
			})

			ResetRuleURLRef()
			BuildCommit = tc.buildCommit

			if got := ResolveRuleURLCommit(); got != tc.want {
				t.Errorf("ResolveRuleURLCommit() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPinRuleURLRef(t *testing.T) {
	tests := []struct {
		name        string
		pin         string
		buildCommit string
		want        string
	}{
		{
			name:        "pin overrides valid BuildCommit",
			pin:         "main",
			buildCommit: "fedcba9876543210fedcba9876543210fedcba98",
			want:        "main",
		},
		{
			name:        "pin overrides empty BuildCommit",
			pin:         "main",
			buildCommit: "",
			want:        "main",
		},
		{
			name:        "pin to arbitrary ref",
			pin:         "some-branch",
			buildCommit: "fedcba9876543210fedcba9876543210fedcba98",
			want:        "some-branch",
		},
		{
			name:        "empty pin returned as-is",
			pin:         "",
			buildCommit: "fedcba9876543210fedcba9876543210fedcba98",
			want:        "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// not parallel: mutates package globals
			origBuild := BuildCommit
			t.Cleanup(func() {
				BuildCommit = origBuild
				ResetRuleURLRef()
			})

			BuildCommit = tc.buildCommit
			PinRuleURLRef(tc.pin)

			if got := ResolveRuleURLCommit(); got != tc.want {
				t.Errorf("ResolveRuleURLCommit() = %q, want %q (pin=%q, BuildCommit=%q)",
					got, tc.want, tc.pin, tc.buildCommit)
			}
		})
	}
}

func TestResetRuleURLRef(t *testing.T) {
	// not parallel: mutates package globals
	origBuild := BuildCommit
	t.Cleanup(func() {
		BuildCommit = origBuild
		ResetRuleURLRef()
	})

	BuildCommit = "fedcba9876543210fedcba9876543210fedcba98"

	// With pin set, pin wins.
	PinRuleURLRef("main")
	if got := ResolveRuleURLCommit(); got != "main" {
		t.Fatalf("after PinRuleURLRef: got %q, want %q", got, "main")
	}

	// After reset, BuildCommit is used again.
	ResetRuleURLRef()
	if got := ResolveRuleURLCommit(); got != "fedcba9876543210fedcba9876543210fedcba98" {
		t.Errorf("after ResetRuleURLRef: got %q, want BuildCommit", got)
	}
}
