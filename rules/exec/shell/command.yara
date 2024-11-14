rule system: medium {
  meta:
    description              = "execute a shell command"
    syscalls                 = "fork,execl"
    ref                      = "https://man7.org/linux/man-pages/man3/system.3.html"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

    filetypes = "elf,macho"

  strings:
    $system = "system" fullword

  condition:
    all of them in (1000..3000)
}

rule php_shell_exec: medium php {
  meta:
    description = "execute a shell command"
    syscalls    = "fork,execl"

    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2015_Resources_agent = "5a61246c9fe8e52347e35664e0c86ab2897d807792008680e04306e6c2104941"
    filetypes                 = "php"

  strings:
    $php = "<?php"
    $ref = /shell_exec[\(\$\w\)]{0,16}/

  condition:
    filesize < 200KB and $php and $ref
}
