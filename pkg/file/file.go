package file

// common values used across malcontent for extracting and reading files.
const (
	DefaultPoolBuffer int64 = 4 * 1024   // 4KB
	ExtractBuffer     int64 = 64 * 1024  // 64KB
	MaxPoolBuffer     int64 = 128 * 1024 // 128KB
	MaxBytes          int64 = 1 << 32    // 2048MB
	ReadBuffer        int64 = 64 * 1024  // 64KB
	ZipBuffer         int64 = 2 * 1024   // 2KB
)
