rule umount {
  meta:
    capability  = "CAP_SYS_SYSADMIN"
    description = "unmount file system"
    syscall     = "umount"

  strings:
    $ref = "umount" fullword

  condition:
    any of them
}
