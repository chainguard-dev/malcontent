rule fd_write: harmless {
  meta:
    description = "write to file descriptor"
    pledge      = "stdio"
    syscall     = "pwrite64"

  strings:
    $ref  = "pwrited" fullword
    $ref2 = "pwrite" fullword
    $ref3 = "pwrite64" fullword

  condition:
    any of them
}

rule fwrite: harmless {
  meta:
    description = "write binary to file descriptor"
    ref         = "https://man7.org/linux/man-pages/man3/fwrite.3p.html"
    pledge      = "stdio"
    syscall     = "pwrite64"

  strings:
    $ref = "fwrite" fullword

  condition:
    any of them
}

rule py_fd_write {
  meta:
    description = "writes to a file handle"
    syscall     = "pwrite"

  strings:
    $write_val      = /\w+\.write\(\w+\)/
    $writelines_val = /\w+\.writelines\(\w+\)/

  condition:
    any of them
}

