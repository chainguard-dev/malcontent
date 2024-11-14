rule pty: medium {
  meta:
    description = "pseudo-terminal access functions"
    ref         = "https://man7.org/linux/man-pages/man3/grantpt.3.html"

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
