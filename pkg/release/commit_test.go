// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"strings"
	"testing"
)

func TestPickCommit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		vcsRev      string
		buildCommit string
		want        string
	}{
		{
			name:        "valid vcs revision takes priority",
			vcsRev:      "0123456789abcdef0123456789abcdef01234567",
			buildCommit: "fedcba9876543210fedcba9876543210fedcba98",
			want:        "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name:        "valid buildCommit when vcs empty",
			vcsRev:      "",
			buildCommit: "fedcba9876543210fedcba9876543210fedcba98",
			want:        "fedcba9876543210fedcba9876543210fedcba98",
		},
		{
			name:        "empty both falls back to main",
			vcsRev:      "",
			buildCommit: "",
			want:        "main",
		},
		{
			name:        "short hex falls through",
			vcsRev:      "0123456789abcdef",
			buildCommit: "",
			want:        "main",
		},
		{
			name:        "mixed case rejected",
			vcsRev:      "0123456789ABCDEF0123456789ABCDEF01234567",
			buildCommit: "",
			want:        "main",
		},
		{
			name:        "non-hex characters rejected",
			vcsRev:      "g123456789abcdef0123456789abcdef01234567",
			buildCommit: "",
			want:        "main",
		},
		{
			name:        "forty-one chars rejected",
			vcsRev:      "0123456789abcdef0123456789abcdef012345678",
			buildCommit: "",
			want:        "main",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pickCommit(tc.vcsRev, tc.buildCommit)
			if got != tc.want {
				t.Errorf("pickCommit(%q, %q) = %q, want %q", tc.vcsRev, tc.buildCommit, got, tc.want)
			}
		})
	}
}

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

func TestResolveCommitStrictFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		vcsRev      string
		buildCommit string
		want        string
		wantErr     bool
	}{
		{
			name:        "valid vcs revision",
			vcsRev:      "0123456789abcdef0123456789abcdef01234567",
			buildCommit: "",
			want:        "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name:        "valid buildCommit when vcs empty",
			vcsRev:      "",
			buildCommit: "fedcba9876543210fedcba9876543210fedcba98",
			want:        "fedcba9876543210fedcba9876543210fedcba98",
		},
		{
			name:        "vcs precedence over buildCommit when both valid",
			vcsRev:      "0123456789abcdef0123456789abcdef01234567",
			buildCommit: "fedcba9876543210fedcba9876543210fedcba98",
			want:        "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name:        "empty both falls back to main rejected",
			vcsRev:      "",
			buildCommit: "",
			wantErr:     true,
		},
		{
			name:    "short hex rejected",
			vcsRev:  "0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "mixed case rejected",
			vcsRev:  "0123456789ABCDEF0123456789ABCDEF01234567",
			wantErr: true,
		},
		{
			name:    "non-hex chars rejected",
			vcsRev:  "g123456789abcdef0123456789abcdef01234567",
			wantErr: true,
		},
		{
			name:    "forty-one chars rejected",
			vcsRev:  "0123456789abcdef0123456789abcdef012345678",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveCommitStrictFrom(tc.vcsRev, tc.buildCommit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveCommitStrictFrom(%q, %q) error = nil, want non-nil", tc.vcsRev, tc.buildCommit)
				}
				if got != "" {
					t.Errorf("resolveCommitStrictFrom(%q, %q) = %q on error, want empty string", tc.vcsRev, tc.buildCommit, got)
				}
				if !strings.Contains(err.Error(), "release commit unresolved") {
					t.Errorf("resolveCommitStrictFrom(%q, %q) error = %v, want it to contain %q", tc.vcsRev, tc.buildCommit, err, "release commit unresolved")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveCommitStrictFrom(%q, %q) error = %v, want nil", tc.vcsRev, tc.buildCommit, err)
			}
			if got != tc.want {
				t.Errorf("resolveCommitStrictFrom(%q, %q) = %q, want %q", tc.vcsRev, tc.buildCommit, got, tc.want)
			}
		})
	}
}

func TestResolveCommitStrictUsesBuildCommitGlobal(t *testing.T) {
	// not parallel: mutates package global
	original := BuildCommit
	t.Cleanup(func() { BuildCommit = original })

	BuildCommit = "fedcba9876543210fedcba9876543210fedcba98"
	got, err := ResolveCommitStrict()
	if err != nil {
		t.Fatalf("ResolveCommitStrict() error = %v, want nil with valid BuildCommit", err)
	}
	// When tests run, vcs.revision is typically empty; the BuildCommit global should win.
	// If vcs.revision is set in the build, that is also valid; accept either as long as 40-hex-lower.
	if !isFortyHexLower(got) {
		t.Errorf("ResolveCommitStrict() = %q, want a 40-char lowercase hex value", got)
	}
}

func TestResolveCommitStrictRejectsInvalidBuildCommitGlobal(t *testing.T) {
	// not parallel: mutates package global
	original := BuildCommit
	t.Cleanup(func() { BuildCommit = original })

	BuildCommit = "not-a-sha"
	// If vcs.revision happens to be a valid 40-hex value during the test run, the strict
	// resolver will accept it. Otherwise, expect a rejection on the "main" fallback.
	if isFortyHexLower(readVCSRevision()) {
		t.Skip("vcs.revision is a valid 40-hex SHA in this build; cannot exercise the rejection path")
	}
	_, err := ResolveCommitStrict()
	if err == nil {
		t.Fatal("ResolveCommitStrict() error = nil, want non-nil when both inputs are invalid")
	}
}
