// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// ociPullTarget serves reg and returns a reference into it plus an already
// authenticated transport. remote adds no per-request retries of its own around
// a *transport.Wrapper, so each pullWithRetry attempt maps to exactly one
// manifest request.
func ociPullTarget(t *testing.T, reg *ociFixtureRegistry) (name.Reference, http.RoundTripper) {
	t.Helper()
	srv, refStr := ociServe(t, reg)
	ref, err := name.ParseReference(refStr)
	if err != nil {
		t.Fatalf("parse reference %q: %v", refStr, err)
	}
	rt, err := transport.NewWithContext(t.Context(), ref.Context().Registry, authn.Anonymous, srv.Client().Transport, []string{ref.Scope(transport.PullScope)})
	if err != nil {
		t.Fatalf("authenticate transport: %v", err)
	}
	return ref, rt
}

func TestPullWithRetry_RetriesOnlyTransientStatuses(t *testing.T) {
	t.Parallel()
	const attempts, window = 3, 60
	exhausted := fmt.Sprintf("pull retry exhausted (attempts=%d, window=%ds)", attempts, window)
	cases := []struct {
		name        string
		status      int
		wantRetried bool
	}{
		{name: "400 bad request fails on the first attempt", status: http.StatusBadRequest},
		{name: "403 forbidden fails on the first attempt", status: http.StatusForbidden},
		{name: "404 not found fails on the first attempt", status: http.StatusNotFound},
		{name: "451 unavailable for legal reasons fails on the first attempt", status: http.StatusUnavailableForLegalReasons},
		{name: "499 client closed request fails on the first attempt", status: 499},
		{name: "408 request timeout is retried", status: http.StatusRequestTimeout, wantRetried: true},
		{name: "429 too many requests is retried", status: http.StatusTooManyRequests, wantRetried: true},
		{name: "500 internal server error is retried", status: http.StatusInternalServerError, wantRetried: true},
		{name: "503 service unavailable is retried", status: http.StatusServiceUnavailable, wantRetried: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := &ociFixtureRegistry{manifestStatus: tc.status}
			ref, rt := ociPullTarget(t, reg)
			img, err := pullWithRetry(t.Context(), ref, rt, staticAnonKeychain{}, attempts, window)
			if img != nil {
				t.Errorf("image: got = %v, want = nil", img)
			}
			var terr *transport.Error
			if !errors.As(err, &terr) {
				t.Fatalf("error: got = %v, want = a *transport.Error", err)
			}
			if terr.StatusCode != tc.status {
				t.Errorf("status: got = %d, want = %d", terr.StatusCode, tc.status)
			}
			wantRequests := 1
			if tc.wantRetried {
				wantRequests = attempts
			}
			if got := len(reg.manifestRequests()); got != wantRequests {
				t.Errorf("manifest requests: got = %d, want = %d", got, wantRequests)
			}
			if got := strings.Contains(err.Error(), exhausted); got != tc.wantRetried {
				t.Errorf("error %q reports the exhausted budget: got = %v, want = %v", err, got, tc.wantRetried)
			}
		})
	}
}

func TestPullWithRetry_BackoffDoublesBetweenAttempts(t *testing.T) {
	t.Parallel()
	reg := &ociFixtureRegistry{manifestStatus: http.StatusServiceUnavailable}
	ref, rt := ociPullTarget(t, reg)
	if _, err := pullWithRetry(t.Context(), ref, rt, staticAnonKeychain{}, 3, 60); err == nil {
		t.Fatal("error: got = nil, want = retry exhausted")
	}
	got := reg.manifestRequests()
	if len(got) != 3 {
		t.Fatalf("manifest requests: got = %d, want = 3", len(got))
	}
	// Jitter only lengthens a wait, so each gap is at least its base backoff.
	for i, minGap := range []time.Duration{100 * time.Millisecond, 200 * time.Millisecond} {
		if gap := got[i+1].Sub(got[i]); gap < minGap {
			t.Errorf("wait before attempt %d: got = %s, want >= %s", i+2, gap, minGap)
		}
	}
}

func TestPullWithRetry_WindowEndsRetries(t *testing.T) {
	t.Parallel()
	const attempts, window = 10, 2
	reg := &ociFixtureRegistry{manifestStatus: http.StatusServiceUnavailable}
	ref, rt := ociPullTarget(t, reg)
	start := time.Now()
	_, err := pullWithRetry(t.Context(), ref, rt, staticAnonKeychain{}, attempts, window)
	elapsed := time.Since(start)
	var terr *transport.Error
	if !errors.As(err, &terr) || terr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("error: got = %v, want = a 503 *transport.Error", err)
	}
	if want := fmt.Sprintf("pull retry exhausted (attempts=%d, window=%ds)", attempts, window); !strings.Contains(err.Error(), want) {
		t.Errorf("error: got = %q, want containing %q", err, want)
	}
	// Backoffs of 0.1s, 0.2s, 0.4s, ... fit several attempts into the window
	// with each wait capped at the time left, and the window ends the loop
	// long before all ten attempts.
	if got := len(reg.manifestRequests()); got < 2 || got >= attempts {
		t.Errorf("manifest requests: got = %d, want in [2, %d)", got, attempts)
	}
	if elapsed < window*time.Second {
		t.Errorf("elapsed: got = %s, want >= %s", elapsed, window*time.Second)
	}
}

func TestPullWithRetry_NoBudgetMakesNoRequest(t *testing.T) {
	t.Parallel()
	const want = "retry budget exhausted"
	cases := []struct {
		name     string
		attempts int
		window   int
	}{
		{name: "zero attempts", attempts: 0, window: 60},
		{name: "window already elapsed", attempts: 3, window: -1},
		// The window, not the attempt count, bounds the loop: once it is spent
		// the call returns at once instead of iterating through the attempts left.
		{name: "window already elapsed ends an unbounded attempt count", attempts: math.MaxInt, window: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := &ociFixtureRegistry{}
			ref, rt := ociPullTarget(t, reg)
			img, err := pullWithRetry(t.Context(), ref, rt, staticAnonKeychain{}, tc.attempts, tc.window)
			if img != nil {
				t.Errorf("image: got = %v, want = nil", img)
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("error: got = %v, want containing %q", err, want)
			}
			if got := len(reg.manifestRequests()); got != 0 {
				t.Errorf("manifest requests: got = %d, want = 0", got)
			}
		})
	}
}
