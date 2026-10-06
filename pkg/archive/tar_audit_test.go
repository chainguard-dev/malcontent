// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"math"
	"slices"
	"strings"
	"testing"
)

// feed writes the stream to the auditor in varied chunk sizes, since the block
// state machine has to survive writes that straddle block boundaries.
func feed(t *testing.T, stream []byte, chunk int) *tarAuditor {
	t.Helper()
	a := newTarAuditor()
	for i := 0; i < len(stream); i += chunk {
		end := min(i+chunk, len(stream))
		if _, err := a.Write(stream[i:end]); err != nil {
			t.Fatalf("Write returned %v; the auditor must never fail a write", err)
		}
	}
	return a
}

func TestTarAuditor(t *testing.T) {
	endMarker := make([]byte, 2*tarBlockSize)

	body := func(content string, fill byte) []byte {
		b := make([]byte, tarBlockSize)
		copy(b, content)
		for i := len(content); i < tarBlockSize; i++ {
			b[i] = fill
		}
		return b
	}

	// A size field may spend all twelve bytes on digits, with no terminator.
	twelveDigits := rawTarHeader("a.txt", 4, tar.TypeReg)
	copy(twelveDigits[124:136], "000000000004")
	// Non-zero bytes directly after the declared content, zeros after them.
	nearPadding := make([]byte, tarBlockSize)
	copy(nearPadding, "data"+strings.Repeat("X", 28))

	tests := []struct {
		name     string
		stream   []byte
		wantFail bool
	}{
		{
			name:     "non-zero padding after a twelve-digit size field",
			stream:   slices.Concat(twelveDigits, nearPadding, endMarker),
			wantFail: true,
		},
		{
			name:     "clean single entry",
			stream:   slices.Concat(rawTarHeader("a.txt", 4, tar.TypeReg), body("data", 0), endMarker),
			wantFail: false,
		},
		{
			name:     "zero padding past the end marker",
			stream:   slices.Concat(rawTarHeader("a.txt", 4, tar.TypeReg), body("data", 0), endMarker, make([]byte, 8192)),
			wantFail: false,
		},
		{
			name:     "non-zero bytes in entry padding",
			stream:   slices.Concat(rawTarHeader("a.txt", 4, tar.TypeReg), body("data", 'X'), endMarker),
			wantFail: true,
		},
		{
			name:     "non-zero bytes past the end marker",
			stream:   slices.Concat(rawTarHeader("a.txt", 4, tar.TypeReg), body("data", 0), endMarker, []byte("hidden")),
			wantFail: true,
		},
		{
			name:     "entry sized to an exact block boundary has no padding",
			stream:   slices.Concat(rawTarHeader("a.txt", tarBlockSize, tar.TypeReg), body("", 'd'), endMarker),
			wantFail: false,
		},
		{
			name:     "header-only entry carries no data blocks",
			stream:   slices.Concat(rawTarHeader("link", 0, tar.TypeSymlink), endMarker),
			wantFail: false,
		},
		{
			// A sparse entry the walk cannot model must be reported, otherwise it
			// becomes a switch for disabling accounting on later entries.
			name:     "gnu sparse entry is reported",
			stream:   slices.Concat(rawTarHeader("sparse", 4, tar.TypeGNUSparse), body("data", 0), endMarker),
			wantFail: true,
		},
		{
			// Only two consecutive zero blocks end the archive.
			name: "single zero block between entries is not the end marker",
			stream: slices.Concat(
				rawTarHeader("a.txt", 4, tar.TypeReg), body("data", 0),
				make([]byte, tarBlockSize),
				rawTarHeader("b.txt", 4, tar.TypeReg), body("data", 0),
				endMarker,
			),
			wantFail: false,
		},
		{
			// archive/tar reads no data for a header-only type whatever its size
			// field says, so the next header follows immediately.
			name: "header-only entry with a non-zero size field carries no data blocks",
			stream: slices.Concat(
				rawTarHeader("link", 100, tar.TypeSymlink),
				rawTarHeader("a.txt", 4, tar.TypeReg), body("data", 0),
				endMarker,
			),
			wantFail: false,
		},
		{
			name: "entry content filling all but two bytes of its block",
			stream: slices.Concat(
				rawTarHeader("a.txt", tarBlockSize-2, tar.TypeReg), body(strings.Repeat("d", tarBlockSize-2), 0),
				rawTarHeader("b.txt", 4, tar.TypeReg), body("data", 0),
				endMarker,
			),
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Chunk sizes chosen to split writes inside and across blocks.
			for _, chunk := range []int{1, 7, 512, 513, len(tt.stream)} {
				if chunk == 0 {
					continue
				}
				a := feed(t, tt.stream, chunk)
				if got := a.err() != nil; got != tt.wantFail {
					t.Errorf("chunk %d: violation = %v (%v), want %v", chunk, got, a.err(), tt.wantFail)
				}
			}
		})
	}
}

func TestParseTarSize(t *testing.T) {
	tests := []struct {
		name   string
		field  []byte
		want   int64
		wantOK bool
	}{
		{name: "octal with NUL terminator", field: []byte("00000000144\x00"), want: 100, wantOK: true},
		{name: "octal with trailing space", field: []byte("00000000144 "), want: 100, wantOK: true},
		{name: "leading spaces before digits", field: []byte("        144\x00"), want: 100, wantOK: true},
		{name: "all padding is zero", field: []byte("            "), want: 0, wantOK: true},
		{name: "largest octal a size field can express", field: []byte("777777777777"), want: 1<<36 - 1, wantOK: true},
		{name: "non-octal digit", field: []byte("00000000009\x00"), want: 0, wantOK: false},
		{name: "non-numeric byte", field: []byte("0000000014z\x00"), want: 0, wantOK: false},
		{
			name:   "gnu base-256",
			field:  []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00},
			want:   256,
			wantOK: true,
		},
		{
			// A negative size is meaningless and must not become a huge count.
			name:   "gnu base-256 negative is rejected",
			field:  []byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
			wantOK: false,
		},
		{
			// 11 payload bytes can express more than an int64 holds.
			name:   "gnu base-256 overflow is rejected",
			field:  []byte{0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			wantOK: false,
		},
		{
			name:   "gnu base-256 zero",
			field:  []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want:   0,
			wantOK: true,
		},
		{
			name:   "gnu base-256 largest int64",
			field:  []byte{0x80, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			want:   math.MaxInt64,
			wantOK: true,
		},
		{name: "octal digits after the terminator are ignored", field: []byte("144\x007777777\x00"), want: 100, wantOK: true},
		{name: "octal largest int64", field: []byte(strings.Repeat("7", 21)), want: math.MaxInt64, wantOK: true},
		{name: "octal past int64 is rejected", field: []byte(strings.Repeat("7", 22)), wantOK: false},
		{name: "octal one past int64 is rejected", field: []byte("1" + strings.Repeat("0", 21)), wantOK: false},
		{
			// The leading payload byte alone puts the value past int64.
			name:   "gnu base-256 value too large in its leading byte is rejected",
			field:  []byte{0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			wantOK: false,
		},
		{name: "empty field", field: nil, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseTarSize(tt.field)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("size = %d, want %d", got, tt.want)
			}
		})
	}
}
