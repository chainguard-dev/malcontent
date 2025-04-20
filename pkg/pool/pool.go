package pool

import (
	"math"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
)

const (
	defaultBuffer    int = 32 * 1024       // 32KB
	maxBuffer        int = 1 * 1024 * 1024 // 1MB
	buffersPerWorker int = 2
)

// SlicePool provides a pool of byte slices.
type SlicePool struct {
	pool sync.Pool
}

// NewBufferPool creates a buffer pool for byte slices.
func NewBufferPool() *SlicePool {
	sp := &SlicePool{}

	sp.pool = sync.Pool{
		New: func() any {
			return make([]byte, defaultBuffer)
		},
	}

	return sp
}

// Get retrieves a byte buffer with the required capacity.
func (sp *SlicePool) Get(size int64) []byte {
	if size <= 0 || uint64(size) >= math.MaxInt64 {
		size = 1
	}

	bufInterface := sp.pool.Get()

	buf, ok := bufInterface.([]byte)
	if !ok || buf == nil {
		return make([]byte, size)
	}

	bufPtr := &buf
	if cap(*bufPtr) < int(size) {
		sp.pool.Put(bufPtr)
		return make([]byte, size)
	}

	return buf[:size]
}

// Put returns a byte buffer to the pool for future reuse.
func (sp *SlicePool) Put(buf []byte) {
	if buf == nil {
		return
	}

	bufPtr := &buf
	if cap(*bufPtr) <= maxBuffer {
		sp.pool.Put(bufPtr)
	}
}

// ScannerPool provides a pool of yara-x scanners.
type ScannerPool struct {
	pool sync.Pool
}

// NewScannerPool creates a scanner pool of the specified size.
func NewScannerPool(yrs *yarax.Rules, count int) *ScannerPool {
	sp := &ScannerPool{}

	sp.pool = sync.Pool{
		New: func() any {
			return yarax.NewScanner(yrs)
		},
	}

	for range count {
		sp.pool.Put(yarax.NewScanner(yrs))
	}
	return sp
}

// Get retrieves a scanner from the scanner pool.
func (sp *ScannerPool) Get() *yarax.Scanner {
	if scanner, ok := sp.pool.Get().(*yarax.Scanner); ok {
		return scanner
	}
	return nil
}

// Put returns a scanner to the scanner pool.
func (sp *ScannerPool) Put(scanner *yarax.Scanner) {
	sp.pool.Put(scanner)
}
