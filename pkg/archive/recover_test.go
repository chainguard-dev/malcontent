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
	"github.com/puzpuzpuz/xsync/v4"

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

// callWithPanicSkip exercises recoverExtractor with a caller-supplied path and
// a config attached to the context so the skip set can be inspected after
// recovery.
func callWithPanicSkip(ctx context.Context, p any, kind, path string) (err error) {
	defer recoverExtractor(ctx, kind, path, &err)
	if p == nil {
		var s *string
		_ = *s
	}
	panic(p)
}

// callWithoutPanicSkip is the no-panic counterpart used to assert the skip set
// stays empty when recovery fires with a nil panic value.
func callWithoutPanicSkip(ctx context.Context, path string) (err error) {
	defer recoverExtractor(ctx, "zip", path, &err)
	return nil
}

func newSkipConfigCtx(t *testing.T) (context.Context, *malcontent.Config) {
	t.Helper()
	cfg := &malcontent.Config{Skipped: xsync.NewMap[string, struct{}]()}
	ctx := malcontent.ContextWithConfig(context.Background(), cfg)
	return ctx, cfg
}

func TestRecoverExtractor_PanicAppendsSkipSet(t *testing.T) {
	cases := []struct {
		name      string
		kind      string
		path      string
		panicWith any
	}{
		{"string panic", "zip", "/synthetic/string.zip", "boom"},
		{"error panic", "tar", "/synthetic/error.tar", errors.New("malformed")},
		{"runtime nil deref", "upx", "/synthetic/nil.upx", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cfg := newSkipConfigCtx(t)
			err := callWithPanicSkip(ctx, tc.panicWith, tc.kind, tc.path)
			if err == nil {
				t.Fatal("expected error from recovered panic, got nil")
			}
			if _, ok := cfg.Skipped.Load(tc.path); !ok {
				t.Fatalf("path %q missing from skip set after recovery", tc.path)
			}
			if got := cfg.Skipped.Size(); got != 1 {
				t.Fatalf("skip set size = %d, want 1", got)
			}
		})
	}
}

func TestRecoverExtractor_NoPanicLeavesSkipSetEmpty(t *testing.T) {
	ctx, cfg := newSkipConfigCtx(t)
	if err := callWithoutPanicSkip(ctx, "/synthetic/quiet.zip"); err != nil {
		t.Fatalf("expected nil from no-panic path, got %v", err)
	}
	if got := cfg.Skipped.Size(); got != 0 {
		t.Fatalf("skip set size = %d, want 0", got)
	}
}

func TestRecoverExtractor_ConcurrentPanicsAllRecorded(t *testing.T) {
	const n = 100
	ctx, cfg := newSkipConfigCtx(t)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		path := fmt.Sprintf("/synthetic/concurrent/%d.zip", i)
		go func(p string) {
			defer wg.Done()
			_ = callWithPanicSkip(ctx, "boom", "zip", p)
		}(path)
	}
	wg.Wait()

	if got := cfg.Skipped.Size(); got != n {
		t.Fatalf("skip set size = %d, want %d", got, n)
	}
	for i := range n {
		path := fmt.Sprintf("/synthetic/concurrent/%d.zip", i)
		if _, ok := cfg.Skipped.Load(path); !ok {
			t.Fatalf("path %q missing from skip set", path)
		}
	}
}
