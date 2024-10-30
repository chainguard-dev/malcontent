rule syscalls: harmless {
  meta:
    pledge      = "proc"
    syscall     = "setsid"
    ref         = "https://man7.org/linux/man-pages/man2/setsid.2.html"
    description = "creates a session and sets the process group ID"

  strings:
    $setsid = "setsid" fullword

  condition:
    any of them
}

