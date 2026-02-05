// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGetContents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		content     []byte
		bufSize     int64
		wantErr     bool
		wantLen     int
		wantContent []byte
	}{
		{
			name:        "empty file",
			content:     []byte{},
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     0,
			wantContent: []byte{},
		},
		{
			name:        "small file",
			content:     []byte("hello world"),
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     11,
			wantContent: []byte("hello world"),
		},
		{
			name:        "file with buffer size 1KB",
			content:     make([]byte, 1024),
			bufSize:     1024,
			wantErr:     false,
			wantLen:     1024,
			wantContent: make([]byte, 1024),
		},
		{
			name:        "file larger than buffer",
			content:     make([]byte, 8192),
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     8192,
			wantContent: make([]byte, 8192),
		},
		{
			name:        "file at ReadBuffer size",
			content:     make([]byte, ReadBuffer),
			bufSize:     ReadBuffer,
			wantErr:     false,
			wantLen:     int(ReadBuffer),
			wantContent: make([]byte, ReadBuffer),
		},
		{
			name:        "file with ExtractBuffer size",
			content:     make([]byte, ExtractBuffer),
			bufSize:     ExtractBuffer,
			wantErr:     false,
			wantLen:     int(ExtractBuffer),
			wantContent: make([]byte, ExtractBuffer),
		},
		{
			name:        "file with MaxPoolBuffer size",
			content:     make([]byte, MaxPoolBuffer),
			bufSize:     MaxPoolBuffer,
			wantErr:     false,
			wantLen:     int(MaxPoolBuffer),
			wantContent: make([]byte, MaxPoolBuffer),
		},
		{
			name:        "file with null bytes",
			content:     []byte{0, 1, 2, 0, 3, 4, 0},
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     7,
			wantContent: []byte{0, 1, 2, 0, 3, 4, 0},
		},
		{
			name:        "file with unicode content",
			content:     []byte("Hello 世界 🌍"),
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     17,
			wantContent: []byte("Hello 世界 🌍"),
		},
		{
			name:        "small buffer still works",
			content:     []byte("test content"),
			bufSize:     4,
			wantErr:     false,
			wantLen:     12,
			wantContent: []byte("test content"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "testfile")

			if err := os.WriteFile(tmpFile, tt.content, 0o644); err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			f, err := os.Open(tmpFile)
			if err != nil {
				t.Fatalf("failed to open test file: %v", err)
			}
			defer f.Close()

			buf := make([]byte, tt.bufSize)

			got, err := GetContents(f, buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetContents() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != tt.wantLen {
				t.Errorf("GetContents() returned %d bytes, want %d", len(got), tt.wantLen)
			}

			if !bytes.Equal(got, tt.wantContent) {
				t.Errorf("GetContents() content mismatch")
			}
		})
	}
}

func TestGetContentsClosedFile(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "testfile")

	if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}

	f.Close()

	buf := make([]byte, DefaultPoolBuffer)
	_, err = GetContents(f, buf)
	if err == nil {
		t.Error("GetContents() should error on closed file, got nil error")
	}
}

func TestGetContentsMaxBytesLimit(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "largefile")

	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	testPattern := []byte("START")
	if _, err := f.Write(testPattern); err != nil {
		f.Close()
		t.Fatalf("failed to write to test file: %v", err)
	}

	chunkSize := 1024 * 1024
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	for range 10 {
		if _, err := f.Write(chunk); err != nil {
			f.Close()
			t.Fatalf("failed to write chunk: %v", err)
		}
	}

	f.Close()

	f, err = os.Open(tmpFile)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	defer f.Close()

	buf := make([]byte, ExtractBuffer)
	got, err := GetContents(f, buf)
	if err != nil {
		t.Fatalf("GetContents() error = %v", err)
	}

	expectedSize := 5 + (10 * chunkSize)
	if len(got) != expectedSize {
		t.Errorf("GetContents() read %d bytes, want %d", len(got), expectedSize)
	}

	if string(got[:5]) != "START" {
		t.Errorf("GetContents() start pattern = %q, want %q", got[:5], "START")
	}
}

func TestGetContentsNilBuffer(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "testfile")

	if err := os.WriteFile(tmpFile, []byte("test content"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	defer f.Close()

	got, err := GetContents(f, nil)
	if err != nil {
		t.Fatalf("GetContents() with nil buffer error = %v", err)
	}

	want := []byte("test content")
	if !bytes.Equal(got, want) {
		t.Errorf("GetContents() = %q, want %q", got, want)
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  int64
		want int64
	}{
		{"DefaultPoolBuffer", DefaultPoolBuffer, 4 * 1024},
		{"ExtractBuffer", ExtractBuffer, 64 * 1024},
		{"MaxPoolBuffer", MaxPoolBuffer, 128 * 1024},
		{"MaxBytes", MaxBytes, 1 << 32},
		{"ReadBuffer", ReadBuffer, 64 * 1024},
		{"ZipBuffer", ZipBuffer, 2 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}
