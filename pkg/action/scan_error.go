package action

import "fmt"

const (
	errMsgScanFailed     = "scan failed"
	errMsgGenerateFailed = "failed to generate file report"
	errMsgNilReport      = "file report is nil"
)

type ErrorType int

const (
	TypeScanError ErrorType = iota
	TypeGenerateError
	TypeNilError
)

type FileReportError struct {
	err    error
	path   string
	reason string
}

func NewFileReportError(err error, path, reason string) *FileReportError {
	return &FileReportError{
		err:    err,
		path:   path,
		reason: reason,
	}
}

func (e *FileReportError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s: %s: %v", e.reason, e.path, e.err)
	}
	return fmt.Sprintf("%s: %s", e.reason, e.path)
}

func (e *FileReportError) Is(target error) bool {
	t, ok := target.(*FileReportError)
	if !ok {
		return false
	}
	return e.path == t.path && e.reason == t.reason
}

func (e *FileReportError) Path() string { return e.path }

func (e *FileReportError) Reason() string { return e.reason }

func (e *FileReportError) Type() ErrorType {
	switch e.reason {
	case errMsgScanFailed:
		return TypeScanError
	case errMsgGenerateFailed:
		return TypeGenerateError
	case errMsgNilReport:
		return TypeNilError
	default:
		return -1
	}
}

func (e *FileReportError) Unwrap() error {
	return e.err
}
