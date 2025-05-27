package action

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"runtime"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"github.com/google/go-cmp/cmp"
)

func TestOCI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clog.FromContext(ctx).With("test", "scan_oci")

	var out bytes.Buffer
	r, err := render.New("json", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	mc := malcontent.Config{
		Concurrency: runtime.NumCPU(),
		IgnoreSelf:  false,
		MinFileRisk: 0,
		MinRisk:     0,
		Renderer:    r,
		Rules:       yrs,
		ScanPaths:   []string{"testdata/static.tar.xz"},
	}
	res, err := Scan(ctx, mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Full(ctx, nil, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	got := out.String()

	td, err := os.ReadFile("testdata/scan_oci")
	if err != nil {
		t.Fatalf("testdata read failed: %v", err)
	}
	want := string(td)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Simple output mismatch: (-want +got):\n%s", diff)
	}
}
