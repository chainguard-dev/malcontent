rule fd_read: harmless {
  meta:
    description = "Reads from file descriptors"
    pledge      = "stdio"
    syscall     = "pread64"

  strings:
    $ref = "pread" fullword

  condition:
    any of them
}

rule fread: harmless {
  meta:
    description = "Read binary from a file descriptor"
    ref         = "https://man7.org/linux/man-pages/man3/fread.3p.html"
    pledge      = "stdio"
    syscall     = "pread644"

  strings:
    $ref = "fread" fullword

  condition:
    any of them
}

rule py_fd_read {
  meta:
    description = "reads from a file handle"
    syscall     = "open,close"

  strings:
    $read_val = /[\w\(\)]{1,32}\.read\(\)/

  condition:
    any of them
}
