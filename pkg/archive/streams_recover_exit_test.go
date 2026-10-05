// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

const (
	streamsExitChildEnv = "MALCONTENT_ARCHIVE_EXIT_ON_PANIC_CHILD"
	// streamsExitMarker is printed only if recovery returns instead of exiting.
	streamsExitMarker = "recovery returned without exiting"
)

// streamsPanicWithExitConfig panics under recoverExtractor with
// ExitOnExtractorPanic set.
func streamsPanicWithExitConfig(t *testing.T) (err error) {
	t.Helper()
	ctx := malcontent.ContextWithConfig(t.Context(), &malcontent.Config{ExitOnExtractorPanic: true})
	defer recoverExtractor(ctx, "gzip", "/synthetic/path.gz", &err)
	panic("synthetic extractor panic")
}

// TestRecoverExtractorExitsWithStatusOneWhenConfigured runs itself in a child
// process because the opt-in fail-loud path terminates the process. The child
// must log the recovery and exit with status 1 without returning to its caller.
func TestRecoverExtractorExitsWithStatusOneWhenConfigured(t *testing.T) {
	if os.Getenv(streamsExitChildEnv) == "1" {
		err := streamsPanicWithExitConfig(t)
		fmt.Println(streamsExitMarker, err)
		return
	}
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRecoverExtractorExitsWithStatusOneWhenConfigured$")
	cmd.Env = append(os.Environ(), streamsExitChildEnv+"=1")
	out, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("child error: got = %v, want = non-zero exit; output:\n%s", err, out)
	}
	if got := exitErr.ExitCode(); got != 1 {
		t.Errorf("child exit code: got = %d, want = 1; output:\n%s", got, out)
	}
	if !bytes.Contains(out, []byte("extractor panic recovered")) {
		t.Errorf("child output: got = %q, want = the recovery log line before exit", out)
	}
	if bytes.Contains(out, []byte(streamsExitMarker)) {
		t.Errorf("child output: got = %q, want = exit before recovery returns", out)
	}
}
