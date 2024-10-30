rule mmap: harmless {
  meta:
    pledge  = "stdio"
    syscall = "mmap"

  strings:
    $ref = "_mmap" fullword

  condition:
    any of them
}
