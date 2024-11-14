rule exec: medium {
  meta:
    description = "executes a command"




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
