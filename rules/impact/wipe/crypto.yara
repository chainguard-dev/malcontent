private rule crypto_elf_or_macho {
  condition:
    uint32(0) == 1179403647 or (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178)
}

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
    filesize < 2MB and crypto_elf_or_macho and all of them
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
    filesize < 20MB and crypto_elf_or_macho and all of them
}
