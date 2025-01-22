package action

import "fmt"

// Error message constants for NewFileReportError reasons.
// If the compiled rules are invalid or the scanner malfunctions, yrs.Scan will fail.
// If mrs is nil or Generate fails, the file report will be nil.
const (
	errMsgUnknown        = "unknown error"
	errMsgScanFailed     = "scan failed"
	errMsgGenerateFailed = "failed to generate file report"
)

type ErrorType int

// Error type iotas.
const (
	// TypeUnknown will be the default of `0`.
	TypeUnknown ErrorType = iota
	// TypeScanError is to be used when compiled rules are invalid or the scan fails otherwise.
	TypeScanError
	// TypeGenerateError is to be used when a file's report cannot be created.
	TypeGenerateError
)

// FileReportError is a custom error type to hold the error, path, and vanity reason.
type FileReportError struct {
	err    error
	path   string
	reason ErrorType
}

// NewFileReportError returns a new FileReportError.
func NewFileReportError(err error, path string, reason ErrorType) *FileReportError {
	return &FileReportError{
		err:    err,
		path:   path,
		reason: reason,
	}
}

func (e *FileReportError) errMsg() string {
	switch e.reason {
	case TypeUnknown:
		return errMsgUnknown
	case TypeScanError:
		return errMsgScanFailed
	case TypeGenerateError:
		return errMsgGenerateFailed
	default:
		return fmt.Sprintf("unknown error type(%d)", e.reason)
	}
}

func (e *FileReportError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("%s: %s", e.errMsg(), e.path)
	}
	return fmt.Sprintf("%s: %s: %v", errMsgUnknown, e.path, e.err)
}

func (e *FileReportError) Is(target error) bool {
	t, ok := target.(*FileReportError)
	if !ok {
		return false
	}
	return e.path == t.path && e.reason == t.reason
}

func (e *FileReportError) Path() string { return e.path }

func (e *FileReportError) Type() ErrorType {
	return e.reason
}

func (e *FileReportError) Unwrap() error {
	return e.err
}
