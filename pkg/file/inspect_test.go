// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// inspectSink receives a byte the truncation test reads, so that the read is
// not optimized away.
var inspectSink byte

func TestInspectContents(t *testing.T) {
	t.Parallel()
	above := int(testMapAbove)
	errInspect := errors.New("inspection failed")
	tests := []struct {
		name    string
		size    int
		inspect func(t *testing.T, path string, b []byte) error
		wantErr string
	}{
		{name: "small file is read whole", size: 4096},
		{name: "large file is inspected whole", size: 4 * above},
		{
			name: "an error from the inspection is returned",
			size: 4096,
			inspect: func(*testing.T, string, []byte) error {
				return errInspect
			},
			wantErr: errInspect.Error(),
		},
	}
	if canMap {
		tests = append(tests, struct {
			name    string
			size    int
			inspect func(t *testing.T, path string, b []byte) error
			wantErr string
		}{
			name: "a large file truncated while inspected fails instead of crashing",
			size: 4 * above,
			inspect: func(t *testing.T, path string, b []byte) error {
				t.Helper()
				if err := os.Truncate(path, 0); err != nil {
					t.Fatalf("truncate: %v", err)
				}
				inspectSink = b[len(b)-1]
				return nil
			},
			wantErr: "changed while it was read",
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			content := deterministicBytes(tt.size)
			f := openTemp(t, content)
			var got []byte
			err := inspectAbove(f, int64(tt.size), testMapAbove, func(b []byte) error {
				got = bytes.Clone(b)
				if tt.inspect != nil {
					return tt.inspect(t, f.Name(), b)
				}
				return nil
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("inspectAbove() error: got = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("inspectAbove() error: got = %v, want = nil", err)
			}
			if !bytes.Equal(got, content) {
				t.Errorf("inspected bytes: got = %d bytes, want = the %d bytes on disk", len(got), len(content))
			}
		})
	}
}

func TestInspectContentsPropagatesOtherPanics(t *testing.T) {
	t.Parallel()
	f := openTemp(t, deterministicBytes(4*int(testMapAbove)))
	defer func() {
		if r := recover(); r != "boom" {
			t.Errorf("recovered: got = %v, want = %q", r, "boom")
		}
	}()
	_ = inspectAbove(f, 4*testMapAbove, testMapAbove, func([]byte) error {
		panic("boom")
	})
	t.Error("inspectAbove() returned, want the inspection's panic")
}
