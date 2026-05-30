// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package archive

import (
	"os/exec"
	"syscall"
)

// applySysProcAttr sets Linux-only process attributes that bound the spawned
// child to the parent's lifetime: Pdeathsig reaps the child if the parent dies
// abruptly, and a fresh process group isolates the child so signals do not bleed
// to or from the parent's group. The group is not actively signalled, so any
// grandchildren the child spawns are bounded only by Pdeathsig, not by a
// group-wide kill.
func applySysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
}
