// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"fmt"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// ociPlatformManifest is one manifest of a test index.
type ociPlatformManifest struct {
	platform    *v1.Platform
	annotations map[string]string
	file        string // the one file in the manifest's image
}

// ociTestIndex builds an index of single-file images.
func ociTestIndex(t *testing.T, manifests ...ociPlatformManifest) v1.ImageIndex {
	t.Helper()
	adds := make([]mutate.IndexAddendum, 0, len(manifests))
	for _, m := range manifests {
		img := ociTestImage(t, []ociTestEntry{{name: m.file, body: m.file}})
		adds = append(adds, mutate.IndexAddendum{
			Add:         img,
			Platform:    m.platform,
			Annotations: m.annotations,
		})
	}
	return mutate.AppendManifests(empty.Index, adds...)
}

func TestOCIWithConfig_Platforms(t *testing.T) {
	t.Parallel()
	amd64 := ociPlatformManifest{platform: &v1.Platform{OS: "linux", Architecture: "amd64"}, file: "amd64.txt"}
	arm64 := ociPlatformManifest{platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, file: "arm64.txt"}
	armv7 := ociPlatformManifest{platform: &v1.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}, file: "armv7.txt"}
	attestation := ociPlatformManifest{
		platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
		annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
		file:        "attestation.txt",
	}
	noPlatform := ociPlatformManifest{file: "no-platform.txt"}
	amd64Again := ociPlatformManifest{platform: &v1.Platform{OS: "linux", Architecture: "amd64"}, file: "amd64-again.txt"}

	cases := []struct {
		name      string
		manifests []ociPlatformManifest // nil pushes a single-manifest image instead of an index
		platforms []string
		want      map[string]string
		wantErr   string
	}{
		{
			name:      "every platform of an index is extracted into its own directory",
			manifests: []ociPlatformManifest{amd64, arm64, armv7},
			want: map[string]string{
				"linux-amd64": "dir", "linux-amd64/amd64.txt": "file:amd64.txt",
				"linux-arm64-v8": "dir", "linux-arm64-v8/arm64.txt": "file:arm64.txt",
				"linux-arm-v7": "dir", "linux-arm-v7/armv7.txt": "file:armv7.txt",
			},
		},
		{
			name:      "a platform filter that selects one platform keeps the root layout",
			manifests: []ociPlatformManifest{amd64, arm64},
			platforms: []string{"linux/arm64"},
			want:      map[string]string{"arm64.txt": "file:arm64.txt"},
		},
		{
			name:      "a filter with a variant matches only that variant",
			manifests: []ociPlatformManifest{amd64, arm64, armv7},
			platforms: []string{"linux/arm/v7", "linux/amd64"},
			want: map[string]string{
				"linux-amd64": "dir", "linux-amd64/amd64.txt": "file:amd64.txt",
				"linux-arm-v7": "dir", "linux-arm-v7/armv7.txt": "file:armv7.txt",
			},
		},
		{
			name:      "attestation and unknown-platform manifests are skipped",
			manifests: []ociPlatformManifest{amd64, attestation, noPlatform},
			want:      map[string]string{"amd64.txt": "file:amd64.txt"},
		},
		{
			name:      "an index without linux/amd64 is extracted",
			manifests: []ociPlatformManifest{arm64},
			want:      map[string]string{"arm64.txt": "file:arm64.txt"},
		},
		{
			name:      "platforms that share a name get distinct directories",
			manifests: []ociPlatformManifest{amd64, amd64Again},
			want: map[string]string{
				"linux-amd64": "dir", "linux-amd64/amd64.txt": "file:amd64.txt",
				"linux-amd64-2": "dir", "linux-amd64-2/amd64-again.txt": "file:amd64-again.txt",
			},
		},
		{
			name:      "a single-manifest image ignores the platform filter",
			platforms: []string{"linux/s390x"},
			want:      map[string]string{"single.txt": "file:single.txt"},
		},
		{
			name:      "a filter that matches nothing is an error",
			manifests: []ociPlatformManifest{amd64, arm64},
			platforms: []string{"linux/s390x"},
			wantErr:   "no image in the index matches platforms linux/s390x",
		},
		{
			name:      "an index with only skipped manifests is an error",
			manifests: []ociPlatformManifest{attestation},
			wantErr:   "no image in the index matches",
		},
		{
			name:      "a malformed platform filter is an error",
			manifests: []ociPlatformManifest{amd64},
			platforms: []string{"linux/arm64/v8/extra"},
			wantErr:   "invalid platform",
		},
	}
	host := ociTestRegistry(t)
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ref := fmt.Sprintf("%s/platforms:case%d", host, i)
			if tc.manifests == nil {
				ociPushImage(t, ref, ociTestImage(t, []ociTestEntry{{name: "single.txt", body: "single.txt"}}))
			} else {
				ociPushIndex(t, ref, ociTestIndex(t, tc.manifests...))
			}
			c := ociTestConfig(0)
			c.OCIPlatforms = tc.platforms
			dir, err := OCIWithConfig(t.Context(), ref, c)
			removeOCIDir(t, dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error: got = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("OCIWithConfig: %v", err)
			}
			ociAssertTree(t, dir, tc.want)
		})
	}
}

func TestPlatformSegment(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   v1.Platform
		want string
	}{
		{name: "os and architecture", in: v1.Platform{OS: "linux", Architecture: "amd64"}, want: "linux-amd64"},
		{name: "variant is appended", in: v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}, want: "linux-arm64-v8"},
		{name: "path separators become dashes", in: v1.Platform{OS: "../..", Architecture: "a/b"}, want: "..-..-a-b"},
		{name: "empty fields leave an unknown placeholder", in: v1.Platform{}, want: "unknown-unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := platformSegment(tc.in); got != tc.want {
				t.Errorf("platformSegment(%+v): got = %q, want = %q", tc.in, got, tc.want)
			}
		})
	}
}
