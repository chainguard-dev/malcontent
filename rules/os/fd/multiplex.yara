rule select {
  meta:
    description = "monitor multiple file descriptors"
    ref         = "https://man7.org/linux/man-pages/man2/select.2.html"
    pledge      = "stdio"
    syscall     = "select"

  strings:
    $ref = "select" fullword

  condition:
    any of them in (1000..3000)
}
