// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/chainguard-dev/clog"
	"github.com/minio/sha256-simd"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// ErrExtractorPanic is the sentinel wrapped by every error returned from
// recoverExtractor. Callers may inspect with errors.Is to branch on panic
// recovery without string matching.
var ErrExtractorPanic = errors.New("extractor panic")

// sha256OfPath returns the lowercase hex SHA-256 digest of p. Used to keep
// raw paths out of structured log fields while preserving correlation.
func sha256OfPath(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// recoverExtractor is a deferred safety net for archive extractors. If the
// extractor panics, the panic is converted to an error and assigned to *err so
// the parent process can mark the archive skipped and continue scanning. The
// caller's named return must be `err`. This function is invoked as
// `defer recoverExtractor(...)` so recover() runs in the deferred frame.
func recoverExtractor(ctx context.Context, kind, path string, err *error) {
	r := recover() //nolint:revive // invoked via defer at every call site
	if r == nil {
		return
	}
	clog.FromContext(ctx).Warn(
		"extractor panic recovered",
		"archive_kind", kind,
		"input_path_sha256", sha256OfPath(path),
		"panic_message", fmt.Sprintf("%v", r),
	)
	if err != nil {
		*err = fmt.Errorf("%w: extractor %s on %s: %v", ErrExtractorPanic, kind, path, r)
	}
	cfg := malcontent.ConfigFromContext(ctx)
	// Publish the panicked path so downstream scan stages can skip it.
	// First-publication-wins semantics keep concurrent recoveries idempotent.
	if cfg != nil && cfg.Skipped != nil {
		cfg.Skipped.LoadOrStore(path, struct{}{})
	}
	// TODO: replace with mal_extractor_panic_total counter once pkg/metrics exists
	if cfg != nil && cfg.ExitOnExtractorPanic {
		// Operator opted into fail-loud on extractor panic.
		// The exit MUST happen at the point of recovery so the panic context
		// (already logged above) is the last record before termination.
		os.Exit(1) //nolint:revive // deep-exit is intentional: operator-opted fail-loud
	}
}
