rule mount_files: medium {
  meta:
    description               = "Parses active mounts (/etc/fstab, /etc/mtab)"
    pledge                    = "stdio"
    ref                       = "https://linux.die.net/man/3/setmntent"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2024_Downloads_036a  = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_311c  = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

  strings:
    $etc_fstab = "/etc/fstab" fullword
    $etc_mtab  = "/etc/mtab" fullword

  condition:
    any of them
}

rule mntent: medium {
  meta:
    description                          = "Parses active mounts (/etc/fstab, /etc/mtab)"
    pledge                               = "stdio"
    ref                                  = "https://linux.die.net/man/3/setmntent"
    hash_2024_Downloads_036a             = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"
    hash_2023_Linux_Malware_Samples_0ad6 = "0ad6c635d583de499148b1ec46d8b39ae2785303e8b81996d3e9e47934644e73"

  strings:
    $setmntent = "setmntent" fullword
    $getmntent = "getmntent" fullword

  condition:
    any of them
}

rule gemntinfo: medium {
  meta:
    description              = "gets information on mounted volumes"
    ref                      = "https://man.freebsd.org/cgi/man.cgi?query=getmntinfo&manpath=FreeBSD+12.1-RELEASE+and+Ports"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"

  strings:
    $ref = "getmntinfo" fullword

  condition:
    any of them
}
