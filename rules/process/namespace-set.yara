rule setns {
  meta:
    capability  = "CAP_SYS_ADMIN"
    syscall     = "setns"
    description = "associate thread or process with a namespace"

  strings:
    $ref = "setns" fullword

  condition:
    any of them
}
