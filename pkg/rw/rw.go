package rw

// common values used when reading and writing data across malcontent.
const (
	ExtractBuffer int64 = 64 * 1024 // 64KB
	MaxBytes      int64 = 1 << 32   // 4GB
	ReadBuffer    int64 = 64 * 1024 // 64KB
	ZipBuffer     int64 = 2 * 1024  // 2KB
)
