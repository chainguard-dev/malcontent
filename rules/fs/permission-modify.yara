
rule chmod : notable {
  meta:
    description = "modifies file permissions"
    pledge = "fattr"
    syscall = "chmod"
    ref = "https://linux.die.net/man/1/chmod"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_adminer = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
  strings:
    $chmod = "chmod" fullword
    $dotChmod = "Chmod" fullword
    $_setmode = "_setmode" fullword
  condition:
    any of them
}

rule fchmod : notamble {
  meta:
    description = "modifies file permissions"
    pledge = "fattr"
    syscall = "fchmodat"
    ref = "https://linux.die.net/man/2/fchmodat"
  strings:
    $fchmod = "fchmod" fullword
    $dotfchmod = ".Fchmod" fullword
    $fchmodat = "fchmodat" fullword
  condition:
    any of them
}
