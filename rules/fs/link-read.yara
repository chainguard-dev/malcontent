rule readlink {
  meta:
    syscall     = "readlink"
    description = "read value of a symbolic link"
    pledge      = "rpath"
    ref         = "https://man7.org/linux/man-pages/man2/readlink.2.html"

  strings:
    $ref  = "readlink" fullword
    $ref2 = "readlinkat" fullword

  condition:
    any of them
}
