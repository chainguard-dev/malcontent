include "rules/global.yara"

rule uname_hostname_encrypt_wipe_kill_small: high {
  meta:
    description = "May encrypt, wipe files, and kill processes"
    filetypes   = "elf,macho"

  strings:
    $encrypt   = "encrypt" fullword
    $wipe      = "wipe" fullword
    $processes = "processes" fullword
    $kill      = "kill" fullword
    $uname     = "uname" fullword
    $hostname  = "hostname" fullword

  condition:
    filesize < 2MB and elf_or_macho and all of them
}

rule uname_hostname_encrypt_wipe_kill: medium {
  meta:
    description = "May encrypt, wipe files, and kill processes"
    filetypes   = "elf,macho"

  strings:
    $encrypt   = "encrypt" fullword
    $wipe      = "wipe" fullword
    $processes = "processes" fullword
    $kill      = "kill" fullword
    $uname     = "uname" fullword
    $hostname  = "hostname" fullword

  condition:
    filesize < 20MB and elf_or_macho and all of them
}
