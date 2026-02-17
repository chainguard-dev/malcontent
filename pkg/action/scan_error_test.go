// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNewFileReportError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		path       string
		reason     ErrorType
		wantPath   string
		wantReason ErrorType
	}{
		{
			name:       "unknown error type",
			err:        errors.New("something broke"),
			path:       "/usr/bin/ls",
			reason:     TypeUnknown,
			wantPath:   "/usr/bin/ls",
			wantReason: TypeUnknown,
		},
		{
			name:       "scan error type",
			err:        errors.New("yara scan failed"),
			path:       "/tmp/archive/extracted/bin",
			reason:     TypeScanError,
			wantPath:   "/tmp/archive/extracted/bin",
			wantReason: TypeScanError,
		},
		{
			name:       "generate error type",
			err:        errors.New("report generation failed"),
			path:       "/var/data/sample.elf",
			reason:     TypeGenerateError,
			wantPath:   "/var/data/sample.elf",
			wantReason: TypeGenerateError,
		},
		{
			name:       "nil underlying error",
			err:        nil,
			path:       "/some/path",
			reason:     TypeUnknown,
			wantPath:   "/some/path",
			wantReason: TypeUnknown,
		},
		{
			name:       "empty path",
			err:        errors.New("error"),
			path:       "",
			reason:     TypeScanError,
			wantPath:   "",
			wantReason: TypeScanError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fre := NewFileReportError(tt.err, tt.path, tt.reason)
			if fre == nil {
				t.Fatal("NewFileReportError returned nil")
			}
			if fre.Path() != tt.wantPath {
				t.Errorf("Path() = %q, want %q", fre.Path(), tt.wantPath)
			}
			if fre.Type() != tt.wantReason {
				t.Errorf("Type() = %d, want %d", fre.Type(), tt.wantReason)
			}
			if !errors.Is(fre.Unwrap(), tt.err) {
				t.Errorf("Unwrap() = %v, want %v", fre.Unwrap(), tt.err)
			}
		})
	}
}

func TestFileReportErrorError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         error
		path        string
		reason      ErrorType
		wantContain []string
	}{
		{
			name:        "with underlying error includes path and error",
			err:         errors.New("underlying cause"),
			path:        "/usr/bin/evil",
			reason:      TypeScanError,
			wantContain: []string{"/usr/bin/evil", "underlying cause"},
		},
		{
			name:        "nil error unknown type uses errMsg format",
			err:         nil,
			path:        "/tmp/file",
			reason:      TypeUnknown,
			wantContain: []string{errMsgUnknown, "/tmp/file"},
		},
		{
			name:        "nil error scan type uses errMsg format",
			err:         nil,
			path:        "/tmp/scan",
			reason:      TypeScanError,
			wantContain: []string{errMsgScanFailed, "/tmp/scan"},
		},
		{
			name:        "nil error generate type uses errMsg format",
			err:         nil,
			path:        "/tmp/gen",
			reason:      TypeGenerateError,
			wantContain: []string{errMsgGenerateFailed, "/tmp/gen"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fre := NewFileReportError(tt.err, tt.path, tt.reason)
			got := fre.Error()
			for _, want := range tt.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("Error() = %q, want it to contain %q", got, want)
				}
			}
		})
	}
}

// TestFileReportErrorErrorFormat verifies the exact format differs based on whether
// the underlying error is nil or non-nil.
func TestFileReportErrorErrorFormat(t *testing.T) {
	t.Parallel()

	// With a non-nil underlying error, the format is: "unknown error: <path>: <err>"
	withErr := NewFileReportError(errors.New("boom"), "/p", TypeScanError)
	got := withErr.Error()
	want := fmt.Sprintf("%s: %s: %v", errMsgUnknown, "/p", errors.New("boom"))
	if got != want {
		t.Errorf("Error() with underlying error = %q, want %q", got, want)
	}

	// With a nil underlying error, the format is: "<errMsg>: <path>"
	withoutErr := NewFileReportError(nil, "/q", TypeScanError)
	got2 := withoutErr.Error()
	want2 := fmt.Sprintf("%s: %s", errMsgScanFailed, "/q")
	if got2 != want2 {
		t.Errorf("Error() without underlying error = %q, want %q", got2, want2)
	}
}

func TestFileReportErrorIs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		a      *FileReportError
		b      error
		wantIs bool
	}{
		{
			name:   "same path and reason matches",
			a:      NewFileReportError(errors.New("err1"), "/usr/bin/ls", TypeScanError),
			b:      NewFileReportError(errors.New("different error"), "/usr/bin/ls", TypeScanError),
			wantIs: true,
		},
		{
			name:   "same path different reason does not match",
			a:      NewFileReportError(errors.New("err"), "/usr/bin/ls", TypeScanError),
			b:      NewFileReportError(errors.New("err"), "/usr/bin/ls", TypeGenerateError),
			wantIs: false,
		},
		{
			name:   "different path same reason does not match",
			a:      NewFileReportError(errors.New("err"), "/usr/bin/ls", TypeScanError),
			b:      NewFileReportError(errors.New("err"), "/usr/bin/cat", TypeScanError),
			wantIs: false,
		},
		{
			name:   "non-FileReportError does not match",
			a:      NewFileReportError(errors.New("err"), "/path", TypeScanError),
			b:      errors.New("regular error"),
			wantIs: false,
		},
		{
			name:   "both empty paths and same reason matches",
			a:      NewFileReportError(nil, "", TypeUnknown),
			b:      NewFileReportError(errors.New("x"), "", TypeUnknown),
			wantIs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.a.Is(tt.b)
			if got != tt.wantIs {
				t.Errorf("Is() = %v, want %v", got, tt.wantIs)
			}
		})
	}
}

// TestFileReportErrorIsViaErrorsIs verifies that errors.Is works through wrapping chains.
func TestFileReportErrorIsViaErrorsIs(t *testing.T) {
	t.Parallel()

	target := NewFileReportError(nil, "/bin/sh", TypeScanError)
	wrapped := fmt.Errorf("outer: %w", target)

	if !errors.Is(wrapped, target) {
		t.Error("errors.Is should find FileReportError through wrapping")
	}

	different := NewFileReportError(nil, "/bin/sh", TypeGenerateError)
	if errors.Is(wrapped, different) {
		t.Error("errors.Is should not match FileReportError with different reason")
	}
}

// TestFileReportErrorAsViaErrorsAs verifies that errors.As correctly extracts
// the FileReportError from a wrapping chain.
func TestFileReportErrorAsViaErrorsAs(t *testing.T) {
	t.Parallel()

	inner := errors.New("root cause")
	fre := NewFileReportError(inner, "/opt/bin/tool", TypeGenerateError)
	wrapped := fmt.Errorf("wrapping: %w", fre)

	var extracted *FileReportError
	if !errors.As(wrapped, &extracted) {
		t.Fatal("errors.As should extract FileReportError from wrapping chain")
	}
	if extracted.Path() != "/opt/bin/tool" {
		t.Errorf("extracted Path() = %q, want %q", extracted.Path(), "/opt/bin/tool")
	}
	if extracted.Type() != TypeGenerateError {
		t.Errorf("extracted Type() = %d, want %d", extracted.Type(), TypeGenerateError)
	}
	if !errors.Is(extracted.Unwrap(), inner) {
		t.Errorf("extracted Unwrap() = %v, want %v", extracted.Unwrap(), inner)
	}
}

// TestFileReportErrorUnwrap verifies that the underlying error is correctly returned.
func TestFileReportErrorUnwrap(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel error")
	fre := NewFileReportError(sentinel, "/path", TypeScanError)

	if !errors.Is(fre.Unwrap(), sentinel) {
		t.Errorf("Unwrap() should return the original error")
	}

	freNil := NewFileReportError(nil, "/path", TypeScanError)
	if freNil.Unwrap() != nil {
		t.Errorf("Unwrap() should return nil when underlying error is nil")
	}
}

// TestErrorTypeConstants verifies the ErrorType iota values are stable,
// since they may be serialized or used in switch statements.
func TestErrorTypeConstants(t *testing.T) {
	t.Parallel()

	if TypeUnknown != 0 {
		t.Errorf("TypeUnknown = %d, want 0", TypeUnknown)
	}
	if TypeScanError != 1 {
		t.Errorf("TypeScanError = %d, want 1", TypeScanError)
	}
	if TypeGenerateError != 2 {
		t.Errorf("TypeGenerateError = %d, want 2", TypeGenerateError)
	}
}

// TestFileReportErrorErrMsg verifies the errMsg method returns expected messages
// for each error type, including the default branch for invalid types.
func TestFileReportErrorErrMsg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		reason  ErrorType
		wantMsg string
	}{
		{
			name:    "unknown type",
			reason:  TypeUnknown,
			wantMsg: errMsgUnknown,
		},
		{
			name:    "scan error type",
			reason:  TypeScanError,
			wantMsg: errMsgScanFailed,
		},
		{
			name:    "generate error type",
			reason:  TypeGenerateError,
			wantMsg: errMsgGenerateFailed,
		},
		{
			name:    "invalid type falls through to default",
			reason:  ErrorType(999),
			wantMsg: "unknown error type(999)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fre := NewFileReportError(nil, "/path", tt.reason)
			// errMsg is exercised through Error() when err is nil
			got := fre.Error()
			if !strings.Contains(got, tt.wantMsg) {
				t.Errorf("Error() = %q, want it to contain %q", got, tt.wantMsg)
			}
		})
	}
}
