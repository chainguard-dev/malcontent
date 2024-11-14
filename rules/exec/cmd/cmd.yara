rule exec: medium {
  meta:
    description = "executes a command"

    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"

  strings:
    $exe_cmd   = /[\w:]{0,32}[Ee]xe[\w]{0,6}C(m|omman)d[\w:]{0,32}/ fullword
    $run_cmd   = /[\w:]{0,32}[rR]un[\w]{0,6}C(m|omman)d[\w:]{0,32}/ fullword
    $start_cmd = /[\w:]{0,32}[sS]tart[\w]{0,6}C(m|omman)d[\w:]{0,32}/ fullword
    $cmdlist   = "cmdlist" fullword

  condition:
    any of them
}

rule ruby_exec: medium {
  meta:
    description = "executes a command"
    filetypes   = "rb"

  strings:
    $require = "require" fullword
    $val     = /exec\(".{2,64}"\)/

  condition:
    filesize < 1MB and $require and $val
}

rule ruby_run_exe: high {
  meta:
    description = "runs an executable program"
    filetypes   = "rb"

  strings:
    $require = "require" fullword
    $val     = /exec\(".{0,64}\.exe"\)/

  condition:
    filesize < 1MB and $require and $val
}
