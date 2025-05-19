rule app_path: medium {
  meta:
    description = "references hardcoded application path"

  strings:
    $ref = /\/Applications\/.{0,32}\.app\/Contents\/MacOS\/[\w \.\-]{0,32}/

  condition:
    any of them
}

private rule applicatons_macho {
  strings:
    $not_jar   = "META-INF/"
    $not_dwarf = "_DWARF"
    $not_kext  = "_.SYMDEF SORTED"

  condition:
    (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178) and none of ($not*)
}

rule macho_app_path: high {
  meta:
    description = "references hardcoded application path"
    filetypes   = "macho"

  strings:
    $ref = /\/Applications\/.{0,32}\.app\/Contents\/MacOS\/[\w \.\-]{0,32}/

  condition:
    applicatons_macho and any of them
}

rule mac_applications: medium {
  meta:
    description = "references /Applications directly"
    filetypes   = "macho"

  strings:
    $ref = "/Applications" fullword

  condition:
    applicatons_macho and any of them
}
