rule seccomp {
  meta:
    description = "operate on Secure Computing state of the process"
    syscall     = "seccomp"
    ref         = "https://man7.org/linux/man-pages/man2/seccomp.2.html"

  strings:
    $uname = "seccomp" fullword

  condition:
    any of them
}
