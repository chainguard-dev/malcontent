rule setgid {
  meta:
    syscall     = "setgid"
    description = "set real and effective group ID of process"
    pledge      = "id"

  strings:
    $ref    = "setgid" fullword
    $not_go = "_syscall.libc_setgid_trampoline"

    // $ref matches inside coreutils' "file that is setgid" help text, so ls's own
    // documentation used to excuse every other setgid reference in the file.
    // Count it instead of checking for it: fire only on a setgid reference the
    // help text does not account for.
    $notsub_ls = "file that is setgid"

  condition:
    $ref and none of ($not_*) and #ref > #notsub_ls
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
