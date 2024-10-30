rule mlock: harmless {
  meta:
    pledge      = "wpath"
    syscall     = "mlock"
    description = "lock a processes virtual address space"
    capability  = "CAP_IPC_LOCK"

  strings:
    $ref  = "mlock" fullword
    $ref2 = "mlock2" fullword
    $ref3 = "mlockall" fullword

  condition:
    any of them
}
