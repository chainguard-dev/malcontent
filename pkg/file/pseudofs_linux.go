// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"os"

	"golang.org/x/sys/unix"
)

// Filesystem magic numbers that golang.org/x/sys/unix does not define.
const (
	configfsMagic = 0x62656570
	fusectlMagic  = 0x65735543
	mqueueMagic   = 0x19800202
)

// isPseudoFS reports whether the directory r is on belongs to a filesystem
// the kernel synthesizes, such as proc or sysfs, rather than one holding
// stored files. Reading such files yields kernel state: /proc/kcore, a
// regular file sized like the address space, reads as kernel memory.
func isPseudoFS(r *os.Root) bool {
	f, err := r.Open(".")
	if err != nil {
		return false
	}
	defer f.Close()
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	var st unix.Statfs_t
	var statErr error
	if err := rc.Control(func(fd uintptr) { statErr = unix.Fstatfs(int(fd), &st) }); err != nil || statErr != nil {
		return false
	}
	switch uint32(st.Type) { // #nosec G115 -- magic numbers are 32 bits wide
	case unix.PROC_SUPER_MAGIC, unix.SYSFS_MAGIC, unix.DEBUGFS_MAGIC, unix.TRACEFS_MAGIC,
		unix.SECURITYFS_MAGIC, unix.CGROUP_SUPER_MAGIC, unix.CGROUP2_SUPER_MAGIC,
		unix.PSTOREFS_MAGIC, unix.BPF_FS_MAGIC, unix.DEVPTS_SUPER_MAGIC, unix.HUGETLBFS_MAGIC,
		unix.EFIVARFS_MAGIC, unix.BINFMTFS_MAGIC, unix.SELINUX_MAGIC, unix.SMACK_MAGIC,
		unix.NSFS_MAGIC, unix.AUTOFS_SUPER_MAGIC, configfsMagic, fusectlMagic, mqueueMagic:
		return true
	}
	return false
}
