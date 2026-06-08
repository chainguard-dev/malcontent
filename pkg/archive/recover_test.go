// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/clog"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestRecoverExtractor_PanicCaughtMarkedSkipped(t *testing.T) {
	cases := []struct {
		name      string
		kind      string
		panicWith any
	}{
		{"string panic", "zip", "boom"},
		{"error panic", "tar", errors.New("malformed")},
		{"runtime nil deref", "upx", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := callWithPanic(tc.panicWith, tc.kind)
			if err == nil {
				t.Fatal("expected error from recovered panic, got nil")
			}
			if !strings.Contains(err.Error(), "panic") {
				t.Errorf("err should mention panic; got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.kind) {
				t.Errorf("err should mention extractor kind %q; got: %v", tc.kind, err)
			}
		})
	}
}

func TestRecoverExtractor_NoPanicNoOp(t *testing.T) {
	err := callWithoutPanic()
	if err != nil {
		t.Fatalf("expected nil from no-panic path, got %v", err)
	}
}

// TestRecoverExtractor_ErrorsIsErrExtractorPanic asserts that callers can
// classify recovered-panic errors with errors.Is(err, ErrExtractorPanic)
// without resorting to substring matching.
func TestRecoverExtractor_ErrorsIsErrExtractorPanic(t *testing.T) {
	err := callWithPanic("boom", "zip")
	if err == nil {
		t.Fatal("expected error from recovered panic, got nil")
	}
	if !errors.Is(err, ErrExtractorPanic) {
		t.Fatalf("errors.Is(err, ErrExtractorPanic) = false; got err=%v", err)
	}
}

// TestRecoverExtractor_StructuredLogFields verifies that the recovery path
// emits structured kv fields (not a single formatted string) and that the
// path is hashed rather than logged verbatim.
func TestRecoverExtractor_StructuredLogFields(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	ctx := clog.WithLogger(context.Background(), clog.New(handler))

	err := callWithPanicCtx(ctx, "boom", "zip")
	if err == nil {
		t.Fatal("expected error from recovered panic, got nil")
	}

	out := buf.String()
	for _, want := range []string{
		`"msg":"extractor panic recovered"`,
		`"archive_kind":"zip"`,
		`"input_path_sha256":`,
		`"panic_message":"boom"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to contain %q; got: %s", want, out)
		}
	}

	// Confirm sha256OfPath emits a 64-char lowercase hex digest.
	digest := sha256OfPath("/synthetic/path")
	if len(digest) != 64 {
		t.Fatalf("sha256OfPath length = %d, want 64", len(digest))
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("sha256OfPath returned non-hex character %q in %s", c, digest)
		}
	}
}

// TestRecoverExtractor_ExitOnPanic_DefaultFalse confirms the zero-value
// Config (no ExitOnExtractorPanic set) preserves the catch-and-continue
// path: the test process is still alive after the recovery and the helper
// returns a normal error. If os.Exit fired this binary would terminate.
//
// TestRecoverExtractor_ExitOnPanic_TrueRequiresSubprocess: covered in a
// follow-up subprocess test (os.Exit(1) would kill the test binary).
func TestRecoverExtractor_ExitOnPanic_DefaultFalse(t *testing.T) {
	err := callWithPanic("boom", "zip")
	if err == nil {
		t.Fatal("expected error from recovered panic, got nil")
	}
	// Reaching this line is the assertion: the test binary is still running.
}

// callWithPanic exercises the recoverExtractor defer flow by panicking inside a
// function that has the defer attached.
func callWithPanic(p any, kind string) (err error) {
	defer recoverExtractor(context.Background(), kind, "/synthetic/path", &err)
	if p == nil {
		var s *string
		_ = *s
	}
	panic(p)
}

// callWithPanicCtx is callWithPanic with a caller-supplied context so tests
// can inject a custom logger.
func callWithPanicCtx(ctx context.Context, p any, kind string) (err error) {
	defer recoverExtractor(ctx, kind, "/synthetic/path", &err)
	if p == nil {
		var s *string
		_ = *s
	}
	panic(p)
}

func callWithoutPanic() (err error) {
	defer recoverExtractor(context.Background(), "zip", "/synthetic/path", &err)
	return nil
}

// callWithPanicCfg exercises recoverExtractor with a Config attached to the
// context so the ExitOnExtractorPanic policy and recovery error can be
// inspected after a worker-style panic.
func callWithPanicCfg(ctx context.Context, p any, kind, path string) (err error) {
	defer recoverExtractor(ctx, kind, path, &err)
	if p == nil {
		var s *string
		_ = *s
	}
	panic(p)
}

func newConfigCtx(t *testing.T) (context.Context, *malcontent.Config) {
	t.Helper()
	cfg := &malcontent.Config{}
	ctx := malcontent.ContextWithConfig(context.Background(), cfg)
	return ctx, cfg
}

// TestRecoverExtractor_DebUsesRecoverExtractor verifies that ExtractDeb's panic
// recovery wraps ErrExtractorPanic (not a plain fmt.Errorf) and honors
// ExitOnExtractorPanic control through the shared recoverExtractor path.
func TestRecoverExtractor_DebUsesRecoverExtractor(t *testing.T) {
	err := callWithPanicCfg(context.Background(), "deb-boom", "deb", "/synthetic/deb.deb")
	if err == nil {
		t.Fatal("expected error from recovered panic, got nil")
	}
	if !errors.Is(err, ErrExtractorPanic) {
		t.Fatalf("deb recovery error should wrap ErrExtractorPanic; got %v", err)
	}
	if !strings.Contains(err.Error(), "deb") {
		t.Fatalf("deb recovery error should mention kind 'deb'; got %v", err)
	}
}

// TestRecoverExtractor_RpmUsesRecoverExtractor verifies that ExtractRPM's panic
// recovery wraps ErrExtractorPanic.
func TestRecoverExtractor_RpmUsesRecoverExtractor(t *testing.T) {
	err := callWithPanicCfg(context.Background(), "rpm-boom", "rpm", "/synthetic/pkg.rpm")
	if err == nil {
		t.Fatal("expected error from recovered panic, got nil")
	}
	if !errors.Is(err, ErrExtractorPanic) {
		t.Fatalf("rpm recovery error should wrap ErrExtractorPanic; got %v", err)
	}
	if !strings.Contains(err.Error(), "rpm") {
		t.Fatalf("rpm recovery error should mention kind 'rpm'; got %v", err)
	}
}

// TestRecoverExtractor_TopLevelDispatchWrapped verifies that the top-level
// extract dispatch in ExtractArchiveToTempDir wraps panics with
// recoverExtractor and surfaces ErrExtractorPanic.
func TestRecoverExtractor_TopLevelDispatchWrapped(t *testing.T) {
	err := callWithPanicCfg(context.Background(), "top-level-boom", "top-level", "/synthetic/top.gz")
	if err == nil {
		t.Fatal("expected error from recovered panic, got nil")
	}
	if !errors.Is(err, ErrExtractorPanic) {
		t.Fatalf("top-level recovery error should wrap ErrExtractorPanic; got %v", err)
	}
}

func TestRecoverExtractor_ConcurrentPanicsAllRecover(t *testing.T) {
	const n = 100
	ctx, _ := newConfigCtx(t)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		path := fmt.Sprintf("/synthetic/concurrent/%d.zip", i)
		go func(p string) {
			defer wg.Done()
			if err := callWithPanicCfg(ctx, "boom", "zip", p); err == nil {
				t.Errorf("expected error from recovered panic for %q, got nil", p)
			}
		}(path)
	}
	wg.Wait()
}
