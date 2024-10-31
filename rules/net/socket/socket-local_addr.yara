rule getsockname: posix low {
  meta:
    description = "get local address of connected socket"
    syscall     = "getsockname"
    ref         = "https://man7.org/linux/man-pages/man2/getsockname.2.html"

  strings:
    $ref = "getsockname" fullword

  condition:
    any of them
}
