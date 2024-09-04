package action

import (
	"bytes"
	"io/fs"
	"os"
	"runtime"
	"testing"

	"github.com/chainguard-dev/bincapz/pkg/bincapz"
	"github.com/chainguard-dev/bincapz/pkg/compile"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/rules"
	thirdparty "github.com/chainguard-dev/bincapz/third_party"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
)

func TestOCI(t *testing.T) {
	t.Parallel()
	ctx := slogtest.Context(t)
	clog.FromContext(ctx).With("test", "scan_oci")

	yrs, err := compile.Recursive(ctx, []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	var out bytes.Buffer
	simple, err := render.New("simple", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	bc := bincapz.Config{
		Concurrency: runtime.NumCPU(),
		IgnoreSelf:  false,
		MinFileRisk: 0,
		MinRisk:     0,
		Renderer:    simple,
		Rules:       yrs,
		ScanPaths:   []string{"testdata/static.tar"},
	}
	res, err := Scan(ctx, bc)
	if err != nil {
		t.Fatal(err)
	}
	if err := simple.Full(ctx, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	got := out.String()

	td, err := os.ReadFile("testdata/scan_oci")
	if err != nil {
		t.Fatalf("testdata read failed: %v", err)
	}
	// Sort the loaded contents to ensure consistent ordering
	want := string(td)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Simple output mismatch: (-want +got):\n%s", diff)
	}
}
