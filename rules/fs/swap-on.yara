rule swapon {
  meta:
    capability  = "CAP_SYS_SYSADMIN"
    description = "start swapping to a file/device"
    syscall     = "swapon"

  strings:
    $ref = "swapon" fullword

  condition:
    any of them
}
