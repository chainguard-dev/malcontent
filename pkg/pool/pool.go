// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"runtime"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/malcontent/pkg/file"
)

// bufferSize is the length of every buffer a BufferPool hands out.
const bufferSize = int(file.ExtractBuffer)

// buffer is the pooled storage. The pool holds pointers to fixed-size arrays
// because a pointer converts to an interface without allocating, which a
// slice header does not, so Put never allocates.
type buffer = [bufferSize]byte

// BufferPool reuses byte buffers of file.ExtractBuffer bytes. Buffers are
// neither zeroed on Get nor cleared on Put, so a caller must write a buffer
// before reading it. The zero value is ready to use, and a BufferPool must not
// be copied after first use.
type BufferPool struct {
	pool sync.Pool
}

// Get returns a buffer of file.ExtractBuffer bytes with unspecified contents.
func (bp *BufferPool) Get() []byte {
	if b, ok := bp.pool.Get().(*buffer); ok {
		return b[:]
	}
	return new(buffer)[:]
}

// Put returns buf, a buffer from Get that the caller no longer uses, to the
// pool. buf may be resliced from its start. Put drops a buffer whose capacity
// differs from the size Get hands out.
func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) != bufferSize {
		return
	}
	bp.pool.Put((*buffer)(buf[:bufferSize]))
}

// ScannerPool provides a pool of yara-x scanners.
type ScannerPool struct {
	scanners  chan *yarax.Scanner
	closeOnce sync.Once
}

// NewScannerPool creates a pool of yara-x scanners. count is clamped to
// between one and runtime.GOMAXPROCS(0): an empty pool blocks Get forever,
// scanning cannot run more concurrently than GOMAXPROCS, and each scanner
// reserves memory mappings, so an oversized pool can exhaust the kernel's
// mapping limit and abort the process.
func NewScannerPool(yrs *yarax.Rules, count int) *ScannerPool {
	count = min(max(count, 1), runtime.GOMAXPROCS(0))
	sp := &ScannerPool{scanners: make(chan *yarax.Scanner, count)}
	for range count {
		sp.scanners <- yarax.NewScanner(yrs)
	}
	return sp
}

// Get retrieves a scanner from the scanner pool, blocking if none are available.
func (sp *ScannerPool) Get(yrs *yarax.Rules) *yarax.Scanner {
	if sp != nil {
		return <-sp.scanners
	}
	// Guard against a nil scanner pool and
	// create a new scanner with the cached rules as a fallback
	return yarax.NewScanner(yrs)
}

// Put returns a scanner to the scanner pool.
func (sp *ScannerPool) Put(scanner *yarax.Scanner) {
	if scanner != nil {
		select {
		case sp.scanners <- scanner:
		default:
		}
	}
}

// Close destroys the pooled scanners. Call it only after every scanner taken
// with Get has been returned, because Put panics on a closed pool. Calls after
// the first do nothing.
func (sp *ScannerPool) Close() {
	sp.closeOnce.Do(func() {
		close(sp.scanners)
		for scanner := range sp.scanners {
			scanner.Destroy()
		}
	})
}
