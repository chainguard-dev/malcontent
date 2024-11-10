rule getpriority: harmless {
  meta:
    syscall = "getpriority"
    pledge  = "proc"

  strings:
    $ref = "getpriority" fullword

  condition:
    any of them
}
