// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestCheckXZ(t *testing.T) {
	t.Parallel()
	small := xzWithDict(t, "hello", 20)
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{name: "stream within the limit", data: small},
		{name: "streams with padding between them", data: slices.Concat(small, make([]byte, 4), small)},
		{name: "stream declaring 4 GiB", data: xzWithDict(t, "hello", 40), wantErr: ErrDecoderWindow},
		{name: "oversized stream after one within the limit", data: slices.Concat(small, xzWithDict(t, "hello", 40)), wantErr: ErrDecoderWindow},
		{name: "truncated stream is left to the decoder", data: small[:20]},
		{name: "no xz stream at all is left to the decoder", data: []byte("not xz")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := checkXZ(bytes.NewReader(tt.data), int64(len(tt.data))); !errors.Is(err, tt.wantErr) {
				t.Errorf("checkXZ error: got = %v, want = %v", err, tt.wantErr)
			}
		})
	}
}

// FuzzWalkers feeds arbitrary input to the stream structure walkers, which
// must neither panic nor read outside the input.
func FuzzWalkers(f *testing.F) {
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(enc.EncodeAll([]byte("hello"), nil))
	_ = enc.Close()
	f.Add(slices.Concat([]byte{0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0}, []byte("abc")))
	f.Add([]byte{0xfd, '7', 'z', 'X', 'Z', 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_ = checkXZ(r, int64(len(data)))
		var sc sidecar
		zstdSkippableFrames(r, int64(len(data)), &sc)
		// Each frame's content comes from the input, behind a label of 22
		// bytes and a newline, and a frame takes at least 8 bytes of input.
		if limit := len(data) + len(data)/8*23; sc.buf.Len() > limit {
			t.Fatalf("sidecar holds %d bytes from %d bytes of input", sc.buf.Len(), len(data))
		}
	})
}
