package action

import (
	"bytes"
	"io/fs"
	"os"
	"regexp"
	"testing"

	"github.com/chainguard-dev/bincapz/pkg/compile"
	"github.com/chainguard-dev/bincapz/pkg/render"
	"github.com/chainguard-dev/bincapz/rules"
	thirdparty "github.com/chainguard-dev/bincapz/third_party"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
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
	ctx := slogtest.TestContextWithLogger(t)
	clog.FromContext(ctx).With("test", "scan_archive")

	yrs, err := compile.Recursive(ctx, []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	var out bytes.Buffer
	simple, err := render.New("simple", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	sp, err := oci(ctx, "cgr.dev/chainguard/static")
	if err != nil {
		t.Fatalf("oci: %v", err)
	}

	bc := Config{
		IgnoreSelf: false,
		IgnoreTags: []string{"harmless"},
		Renderer:   simple,
		Rules:      yrs,
		ScanPaths:  []string{sp},
	}
	res, err := Scan(ctx, bc)
	if err != nil {
		t.Fatal(err)
	}
	if err := simple.Full(ctx, res); err != nil {
		t.Fatalf("full: %v", err)
	}

	// Remove the header since it is not deterministic
	// due to the usage of temporary directories
	idx := bytes.IndexByte(out.Bytes(), '\n')
	out.Next(idx + 1)

	got := reduceMarkdown(out.String())

	td, err := os.ReadFile("testdata/scan_oci")
	if err != nil {
		t.Fatalf("testdata read failed: %v", err)
	}
	want := reduceMarkdown(string(td))
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
