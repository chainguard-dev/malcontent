// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package archive

import (
	"os/exec"
	"syscall"
)

// applySysProcAttr sets Linux-only process attributes that bound the spawned
// child to the parent's lifetime: a fresh process group lets us signal the
// whole tree, and Pdeathsig reaps the child if the parent dies abruptly.
func applySysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
}
