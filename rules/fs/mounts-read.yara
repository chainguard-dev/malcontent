rule mount_files: medium {
  meta:
    description = "Parses active mounts (/etc/fstab, /etc/mtab)"
    pledge      = "stdio"
    ref         = "https://linux.die.net/man/3/setmntent"

  strings:
    $etc_fstab = "/etc/fstab" fullword
    $etc_mtab  = "/etc/mtab" fullword

  condition:
    any of them
}

rule mntent: medium {
  meta:
    description = "Parses active mounts (/etc/fstab, /etc/mtab)"
    pledge      = "stdio"
    ref         = "https://linux.die.net/man/3/setmntent"

  strings:
    $setmntent = "setmntent" fullword
    $getmntent = "getmntent" fullword

  condition:
    any of them
}

rule gemntinfo: medium {
  meta:
    description = "gets information on mounted volumes"
    ref         = "https://man.freebsd.org/cgi/man.cgi?query=getmntinfo&manpath=FreeBSD+12.1-RELEASE+and+Ports"

  strings:
    $ref = "getmntinfo" fullword

  condition:
    any of them
}
