rule setgroups {
  meta:
    syscall     = "setgroups"
    description = "set group access list"
    pledge      = "id"

  strings:
    $ref = "setgroups" fullword
    $go  = "_syscall.libc_setgroups_trampoline"

  condition:
    $ref and not $go
}
