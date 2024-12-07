rule fd_print: low {
  meta:
    description = "print to file descriptor"
    pledge      = "stdio"
    syscall     = "pwrite64"

  strings:
    $ref = "dprintf" fullword

  condition:
    any of them
}
