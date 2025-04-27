package pool

import (
	"math"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
)

const (
	defaultBuffer int = 4 * 1024   // 4KB
	maxBuffer     int = 128 * 1024 // 128KB
)

// BufferPool provides a pool of byte slices for use as buffers.
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a pool of byte slices.
func NewBufferPool(count int) *BufferPool {
	bp := &BufferPool{}

	bp.pool = sync.Pool{
		New: func() any {
			return make([]byte, defaultBuffer)
		},
	}

	for range count {
		buffer := make([]byte, defaultBuffer)
		bp.pool.Put(&buffer)
	}

	return bp
}

// Get retrieves a byte buffer with the required capacity.
func (bp *BufferPool) Get(size int64) []byte {
	if size <= 0 || uint64(size) >= math.MaxInt64 {
		size = 1
	}

	bufInterface := bp.pool.Get()

	buf, ok := bufInterface.([]byte)
	if !ok || buf == nil {
		return make([]byte, size)
	}

	bufPtr := &buf
	if cap(*bufPtr) < int(size) {
		bp.pool.Put(bufPtr)
		return make([]byte, size)
	}

	return buf[:size]
}

// Put returns a byte buffer to the pool for future reuse.
func (bp *BufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	clear(buf)
	bufPtr := &buf
	if cap(*bufPtr) <= maxBuffer {
		bp.pool.Put(bufPtr)
	}
}

// ScannerPool provides a pool of yara-x scanners.
type ScannerPool struct {
	pool sync.Pool
}

// NewScannerPool creates a pool containing the specified number of yara-x scanners.
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
