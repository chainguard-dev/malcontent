rule mkfifo {
  meta:
    pledge      = "wpath"
    syscall     = "mknod"
    description = "make a FIFO special file (a named pipe)"

  strings:
    $ref = "mkfifo" fullword

  condition:
    any of them
}

rule mkfifoat {
  meta:
    pledge      = "wpath"
    syscall     = "mknod"
    description = "make a FIFO special file (a named pipe)"

  strings:
    $ref = "mkfifoat" fullword

  condition:
    any of them
}
