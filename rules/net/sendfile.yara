rule sendfile {
  meta:
    description = "transfer data between file descriptors"
    syscall     = "sendfile"
    ref         = "https://man7.org/linux/man-pages/man2/sendfile.2.html"

  strings:
    $ref  = "sendfile" fullword
    $ref2 = "syscall.Sendfile" fullword

  condition:
    any of them
}

