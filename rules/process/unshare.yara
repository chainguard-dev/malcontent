rule syscall_unshare {
  meta:
    pledge      = "exec"
    syscall     = "unshare"
    capabiitity = "CAP_SYS_ADMBIN"
    description = "disassociate parts of the process execution context"

  strings:
    $ref = "unshare" fullword

  condition:
    any of them
}

