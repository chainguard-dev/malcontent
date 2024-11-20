rule setuid {
  meta:
    syscall     = "setuid"
    description = "set real and effective user ID of current process"
    pledge      = "id"
    capability  = "CAP_SETUID"
    ref         = "https://man7.org/linux/man-pages/man2/setuid.2.html"

  strings:
    $ref    = "setuid" fullword
    $not_go = "_syscall.libc_setuid_trampoline"
    $not_ls = "file that is setuid"

  condition:
    $ref and none of ($not*)
}

rule seteuid {
  meta:
    syscall     = "seteuid"
    description = "set effective user ID of current process"
    pledge      = "id"
    ref         = "https://man7.org/linux/man-pages/man2/seteuid.2.html"
    capability  = "CAP_SETUID"

  strings:
    $ref = "seteuid" fullword

  condition:
    any of them
}

rule setreuid {
  meta:
    syscall     = "setreuid"
    description = "set real and effective user ID of current process"
    pledge      = "id"
    capability  = "CAP_SETUID"
    ref         = "https://man7.org/linux/man-pages/man2/setreuid.2.html"

  strings:
    $ref = "setreuid" fullword

  condition:
    any of them
}

rule setresuid {
  meta:
    syscall     = "setresuid"
    description = "set real, effective, and saved user ID of process"
    pledge      = "id"
    ref         = "https://man7.org/linux/man-pages/man2/setresuid.2.html"
    capability  = "CAP_SETUID"

  strings:
    $ref = "setresuid" fullword

  condition:
    any of them
}

rule setfsuid {
  meta:
    syscall     = "setfsuid"
    description = "set user identity used for filesystem checks"
    pledge      = "id"
    ref         = "https://man7.org/linux/man-pages/man2/setfsuid.2.html"
    capability  = "CAP_SETUID"

  strings:
    $ref = "setfsuid" fullword

  condition:
    any of them
}

rule ruby_setuid_0: high {
  meta:
    description = "sets uid to 0 (root)"

  strings:
    $ref = "setuid(0)" fullword

  condition:
    any of them
}

