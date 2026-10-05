// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package release

import "testing"

func TestVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		build string
		want  string
	}{
		{"unstamped build reports the compiled-in ID", "", ID},
		{"stamped release build reports the stamped version", "v9.8.7", "v9.8.7"},
		{"stamped snapshot build is reported verbatim", "1.27.0-next", "1.27.0-next"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Version(tt.build); got != tt.want {
				t.Errorf("Version(%q): got = %q, want = %q", tt.build, got, tt.want)
			}
		})
	}
}
