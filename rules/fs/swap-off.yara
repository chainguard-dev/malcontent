rule swapoff {
  meta:
    capability  = "CAP_SYS_SYSADMIN"
    description = "stop swapping to a file/device"
    syscall     = "swapoff"

  strings:
    $ref = "swapoff" fullword

  condition:
    any of them
}
