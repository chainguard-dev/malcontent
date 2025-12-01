package file

// common values used across malcontent for extracting and reading files.
const (
	ExtractBuffer       = 64 * 1024 // 64KB
	MaxBytes            = 1 << 32   // 2048MB
	ReadBuffer    int64 = 64 * 1024 // 64KB
	ZipBuffer           = 2 * 1024  // 2KB
)
