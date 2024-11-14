rule pty: medium {
  meta:
    description              = "pseudo-terminal access functions"
    ref                      = "https://man7.org/linux/man-pages/man3/grantpt.3.html"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"

  strings:
    $grantpt      = "grantpt" fullword
    $ptsname      = "ptsname" fullword
    $posix_openpt = "posix_openpt" fullword
    $unlockpt     = "unlockpt" fullword

  condition:
    2 of them
}

rule linux_pty: medium {
  meta:
    description = "pseudo-terminal access functions"

  strings:
    $linuxpty = "LinuxPty"
    $forkpty  = "forkpty" fullword

  condition:
    any of them
}

rule go_pty: medium {
  meta:
    description = "pseudo-terminal access from Go"
    ref         = "https://github.com/creack/pty"

  strings:
    $ref = "creack/pty"

  condition:
    filesize < 10MB and any of them
}

rule go_pty_socket: high {
  meta:
    description = "pseudo-terminal access from Go"
    ref         = "https://github.com/creack/pty"

  strings:
    $ref = "creack/pty"
    $o2  = "socket" fullword
    $o3  = "secret" fullword

    $bin_sh   = "/bin/sh"
    $bin_bash = "/bin/bash"
    $bin_zsh  = "/bin/zsh"

  condition:
    filesize < 10MB and $ref and any of ($o*) and any of ($bin*)
}
