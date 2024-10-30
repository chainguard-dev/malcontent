rule chroot {
  meta:
    capability  = "CAP_SYS_CHROOT"
    syscall     = "chroot"
    description = "change the location of root for the process"

  strings:
    $ref = "chroot" fullword

  condition:
    any of them
}
