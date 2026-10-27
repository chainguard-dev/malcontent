// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"fmt"
	"os"
	"runtime/debug"
)

// InspectContents calls inspect with the full contents of f, a regular file
// opened for reading whose Stat size is size (> 0), as ReadContents reads
// them, but without copying a large file: one above 32,000,000 bytes is
// memory-mapped where the platform supports it. f may be one that something
// else truncates while inspect runs. A read of a mapped page past the new end
// of the file then fails InspectContents with an error instead of ending the
// process, so inspect must read the bytes only in Go code on the calling
// goroutine, as hashing and type detection do, and must not keep them. Pass
// bytes that yara-x scans through ReadContents instead.
func InspectContents(f *os.File, size int64, inspect func([]byte) error) error {
	return inspectAbove(f, size, mapThreshold, inspect)
}

// inspectAbove is InspectContents with the mapping threshold as a
// parameter: files whose size is above mapAbove are mapped where possible.
func inspectAbove(f *os.File, size, mapAbove int64, inspect func([]byte) error) (err error) {
	c, err := loadContents(f, size, mapAbove)
	if err != nil {
		return err
	}
	defer c.Close()
	if !c.mapped {
		return inspect(c.Bytes())
	}

	// A fault on a page of the mapping becomes a panic whose value reports
	// the faulting address; any other panic is inspect's own.
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if _, fault := r.(interface{ Addr() uintptr }); !fault {
			panic(r)
		}
		err = fmt.Errorf("%s changed while it was read: %v", f.Name(), r)
	}()
	return inspect(c.Bytes())
}
