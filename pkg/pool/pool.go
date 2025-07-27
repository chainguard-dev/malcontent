package pool

import (
	"math"
	"runtime"
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
			buffer := make([]byte, defaultBuffer)
			return &buffer
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

	bufPtr, ok := bufInterface.(*[]byte)
	if !ok {
		return make([]byte, size)
	}

	if bufPtr != nil && cap(*bufPtr) < int(size) {
		bp.pool.Put(bufPtr)
		return make([]byte, size)
	}

	return (*bufPtr)[:size]
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
	scanners  chan *yarax.Scanner
	pinner    *runtime.Pinner
	closeOnce sync.Once
}

// NewScannerPool creates a pool containing the specified number of yara-x scanners.
func NewScannerPool(yrs *yarax.Rules, count int) *ScannerPool {
	sp := &ScannerPool{
		scanners: make(chan *yarax.Scanner, count),
		pinner:   &runtime.Pinner{},
	}

	for range count {
		scanner := yarax.NewScanner(yrs)
		// Pin the scanner in memory to prevent GC movement
		sp.pinner.Pin(scanner)
		sp.scanners <- scanner
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

// Close destroys all active scanners.
// Currently unused.
func (sp *ScannerPool) Close() {
	sp.closeOnce.Do(func() {
		sp.pinner.Unpin()
		close(sp.scanners)
		for scanner := range sp.scanners {
			scanner.Destroy()
		}
	})
}
