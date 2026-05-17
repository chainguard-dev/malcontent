// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package archive

import "os/exec"

// applySysProcAttr is a no-op on non-Linux platforms; SysProcAttr fields used
// by the Linux variant (Setpgid, Pdeathsig) have no portable equivalent.
func applySysProcAttr(_ *exec.Cmd) {}
