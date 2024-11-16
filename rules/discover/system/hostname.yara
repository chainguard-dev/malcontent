rule gethostname {
  meta:
    pledge      = "sysctl"
    syscall     = "sysctl"
    description = "get computer host name"
    ref         = "https://man7.org/linux/man-pages/man2/sethostname.2.html"

  strings:
    $gethostname = "gethostname"
    $proc        = "/proc/sys/kernel/hostname"
    $python      = "socket.gethostname"
    $nodejs      = "os.hostname()"
    $js          = "os.default.hostname"

  condition:
    any of them
}
