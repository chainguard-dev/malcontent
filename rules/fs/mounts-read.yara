rule mount_files: medium {
  meta:
    description = "Parses active mounts (/etc/fstab, /etc/mtab)"
    pledge      = "stdio"
    ref         = "https://linux.die.net/man/3/setmntent"

    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

  strings:
    $etc_fstab = "/etc/fstab" fullword
    $etc_mtab  = "/etc/mtab" fullword

  condition:
    any of them
}

rule mntent: medium {
  meta:
    description              = "Parses active mounts (/etc/fstab, /etc/mtab)"
    pledge                   = "stdio"
    ref                      = "https://linux.die.net/man/3/setmntent"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"

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
