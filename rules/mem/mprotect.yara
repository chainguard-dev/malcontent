rule mprotect: harmless {
  meta:
    pledge  = "stdio"
    syscall = "mprotect"

  strings:
    $ref = "mprotect" fullword

  condition:
    any of them
}
