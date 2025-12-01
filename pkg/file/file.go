package file

// common values used across malcontent for extracting and reading files.
const (
	DefaultPoolBuffer int   = 4 * 1024   // 4KB
	ExtractBuffer           = 64 * 1024  // 64KB
	MaxPoolBuffer     int   = 128 * 1024 // 128KB
	MaxBytes                = 1 << 32    // 2048MB
	ReadBuffer        int64 = 64 * 1024  // 64KB
	ZipBuffer               = 2 * 1024   // 2KB
)
