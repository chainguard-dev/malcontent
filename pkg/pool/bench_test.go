// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package pool

import "testing"

// BenchmarkBufferPoolGetPut measures taking a buffer and returning it, as
// every extractor does once per archive or archive entry.
func BenchmarkBufferPoolGetPut(b *testing.B) {
	var bp BufferPool
	b.ReportAllocs()
	for b.Loop() {
		buf := bp.Get()
		buf[0] = 1
		bp.Put(buf)
	}
}

// BenchmarkBufferPoolGetPutParallel measures the same under contention from
// concurrent zip entry workers.
func BenchmarkBufferPoolGetPutParallel(b *testing.B) {
	var bp BufferPool
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := bp.Get()
			buf[0] = 1
			bp.Put(buf)
		}
	})
}
