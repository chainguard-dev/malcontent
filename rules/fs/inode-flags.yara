rule ioctl_iflags {
  meta:
    pledge      = "wpath"
    syscall     = "ioctl_iflags"
    description = "ioctl operations for inode flags"
    capability  = "CAP_FOWNER"

  strings:
    $ioctl = "ioctl_iflags" fullword

  condition:
    any of them
}
