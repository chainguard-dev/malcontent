// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"os"
	"testing"
)

// benchInput is a file name and its contents for the detection benchmarks.
type benchInput struct {
	name    string
	content []byte
}

// benchInputs returns an ELF binary, a shell script, a JSON document, a zip
// archive, and a gzip stream, each under a name that does not by itself decide
// the kind.
func benchInputs(b *testing.B) []benchInput {
	b.Helper()
	read := func(path string) []byte {
		data, err := os.ReadFile(path)
		if err != nil {
			b.Fatalf("ReadFile(%q): %v", path, err)
		}
		return data
	}
	return []benchInput{
		{"ls", read("testdata/ls")},
		{"test.sh", read("testdata/test.sh")},
		{"data.json", jsonDocument()},
		{"bundle.zip", zipArchive(b)},
		{"payload.gz", gzipStream(b, jsonDocument())},
	}
}

func BenchmarkDetect(b *testing.B) {
	for _, in := range benchInputs(b) {
		b.Run(in.name, func(b *testing.B) {
			b.SetBytes(int64(len(in.content)))
			b.ReportAllocs()
			for b.Loop() {
				Detect(b.Context(), in.name, in.content)
			}
		})
	}
}

// BenchmarkFile measures detection including the preamble and read, over the
// same inputs as BenchmarkDetect.
func BenchmarkFile(b *testing.B) {
	for _, in := range benchInputs(b) {
		b.Run(in.name, func(b *testing.B) {
			path := writeFixture(b, in.name, in.content)
			b.SetBytes(int64(len(in.content)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := File(b.Context(), path); err != nil {
					b.Fatalf("File(%q): %v", path, err)
				}
			}
		})
	}
}

// BenchmarkIsZlibStream measures confirming a zlib stream and rejecting a
// header that fails the check bits.
func BenchmarkIsZlibStream(b *testing.B) {
	inputs := []benchInput{
		{"stream", zlibStream(b, zlibPayload, 6)},
		{"bad header", []byte{0x78, 0x9d, 0x00, 0x00}},
	}
	for _, in := range inputs {
		b.Run(in.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				isZlibStream(in.content)
			}
		})
	}
}

func BenchmarkGetExt(b *testing.B) {
	paths := []string{
		"/usr/bin/ls",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/home/user/project/src/main.go",
		"/tmp/archive/pkg-1.2.3.tar.gz",
		"/opt/tools/composer-2.7.7",
		"/var/lib/apk/db/installed",
		"node_modules/lodash/package.json",
		"/usr/share/man/man1/ls.1",
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, p := range paths {
			GetExt(p)
		}
	}
}
