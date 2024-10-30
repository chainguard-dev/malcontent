rule mknod {
  meta:
    pledge      = "wpath"
    syscall     = "mknod"
    capability  = "CAP_MKNOD"
    description = "create device files"
    ref         = "https://man7.org/linux/man-pages/man2/mknod.2.html"

  strings:
    $ref = "mknod" fullword

  condition:
    any of them
}

rule mknodat {
  meta:
    pledge      = "wpath"
    syscall     = "mknodat"
    capability  = "CAP_MKNOD"
    description = "create device files"
    ref         = "https://man7.org/linux/man-pages/man2/mknodat.2.html"

  strings:
    $ref2 = "mknodat" fullword

  condition:
    any of them
}
