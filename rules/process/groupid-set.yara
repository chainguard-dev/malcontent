rule setgid {
  meta:
    syscall     = "setgid"
    description = "set real and effective group ID of process"
    pledge      = "id"

  strings:
    $ref    = "setgid" fullword
    $not_go = "_syscall.libc_setgid_trampoline"
    $not_ls = "file that is setgid"

  condition:
    $ref and none of ($not*)
}

rule setegid {
  meta:
    syscall     = "setegid"
    description = "set effective group ID of process"
    pledge      = "id"

  strings:
    $ref = "setegid" fullword

  condition:
    any of them
}

rule setregid {
  meta:
    syscall     = "setregid"
    description = "set real and effective group ID of process"
    pledge      = "id"

  strings:
    $ref = "setregid" fullword

  condition:
    any of them
}

rule setresgid {
  meta:
    syscall     = "setresgid"
    description = "set real, effective, and saved group ID of process"
    pledge      = "id"

  strings:
    $ref = "setresgid" fullword

  condition:
    any of them
}
