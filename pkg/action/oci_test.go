package action

import (
	"bytes"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
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

func reduceMarkdown(s string) string {
	spaceRe := regexp.MustCompile(` +`)
	dashRe := regexp.MustCompile(` -`)

	s = spaceRe.ReplaceAllString(s, " ")
	s = dashRe.ReplaceAllString(s, " ")
	return s
}

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
		IgnoreSelf: false,
		IgnoreTags: []string{"harmless"},
		Renderer:   simple,
		Rules:      yrs,
		ScanPaths:  []string{"cgr.dev/chainguard/static"},
		OCI:        true,
	}
	res, err := Scan(ctx, bc)
	if err != nil {
		t.Fatal(err)
	}
	if err := simple.Full(ctx, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	// Sort the output to ensure consistent ordering
	// This is non-deterministic due to multiple files being scanned
	sorted := func(input []byte) []byte {
		lines := strings.Split(string(input), "\n")
		sort.Strings(lines)
		return []byte(strings.Join(lines, "\n"))
	}
	sortedOut := sorted(out.Bytes())
	got := string(sortedOut)

	td, err := os.ReadFile("testdata/scan_oci")
	if err != nil {
		t.Fatalf("testdata read failed: %v", err)
	}
	// Sort the loaded contents to ensure consistent ordering
	sortedWant := sorted(td)
	want := string(sortedWant)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Simple output mismatch: (-want +got):\n%s", diff)
	}
}
