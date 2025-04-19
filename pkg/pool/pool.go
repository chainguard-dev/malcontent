package pool

import (
	"sync"
)

const (
	defaultBuffer    int = 32 * 1024
	maxBuffer        int = 1 * 1024 * 1024
	buffersPerWorker int = 2
)

// BufferPoolConfig contains configuration for the buffer pool.
type BufferPoolConfig struct {
	Concurrency int
}

// SlicePool provides a pool of byte slices with reduced contention.
type SlicePool struct {
	pool    sync.Pool
	counter uint32
	size    int
}

// NewBufferPool creates a buffer pool sized according to concurrency.
func NewBufferPool(config BufferPoolConfig) *SlicePool {
	poolSize := max(1, config.Concurrency*buffersPerWorker)

	sp := &SlicePool{
		size:    poolSize,
		counter: 0,
	}

	sp.pool = sync.Pool{
		New: func() any {
			return make([]byte, defaultBuffer)
		},
	}

	return sp
}

// Get retrieves a byte buffer with the required capacity.
func (sp *SlicePool) Get(requiredSize int64) []byte {
	if requiredSize <= 0 {
		requiredSize = 1
	}

	bufInterface := sp.pool.Get()

	buf, ok := bufInterface.([]byte)
	if !ok || buf == nil {
		return make([]byte, requiredSize)
	}

	bufPtr := &buf
	if cap(*bufPtr) < int(requiredSize) {
		sp.pool.Put(bufPtr)
		return make([]byte, requiredSize)
	}

	return buf[:requiredSize]
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
