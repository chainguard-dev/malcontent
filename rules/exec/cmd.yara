
rule exec : medium {
  meta:
    description = "executes a command"
    hash_2023_0xShell_adminer = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
  strings:
    $exe_cmd = /[\w:]{0,32}[Ee]xe[\w]{0,6}C(m|omman)d[\w:]{0,32}/ fullword
    $run_cmd = /[\w:]{0,32}[rR]un[\w]{0,6}C(m|omman)d[\w:]{0,32}/ fullword
    $start_cmd = /[\w:]{0,32}[sS]tart[\w]{0,6}C(m|omman)d[\w:]{0,32}/ fullword
    $cmdlist = "cmdlist" fullword
  condition:
    any of them
}
