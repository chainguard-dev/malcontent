// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs every test in this package under goleak so that any
// goroutine leaked past process exit fails the suite. The cgo runtime
// shipped with yara-x spawns long-lived background threads that are
// not Go goroutines, so they do not appear in the stack snapshot and
// require no explicit ignore list.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
