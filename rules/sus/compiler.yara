rule archaic_gcc: medium {
  meta:
    description = "built by an ancient version of GCC"
    filetypes   = "elf,macho"

  strings:
    $gcc_v4   = /GCC: \([\w \.\-\~]{1,128}\) 4\.\d{1,16}\.\d{1,128}/
    $not_nacl = "NACLVERBOSITY"

  condition:
    $gcc_v4 and none of ($not*)
}

rule small_opaque_archaic_gcc: high linux {
  meta:
    description = "small and built by an ancient version of GCC"
    filetypes   = "elf,macho"

  strings:
    $gcc_v4           = /GCC: \([\w \.\-\~]{1,128}\) 4\.\d{1,16}\.\d{1,128}/
    $fork             = "fork"
    $not_nacl         = "NACLVERBOSITY"
    $not_usage        = "usage" fullword
    $not_Usage        = "Usage" fullword
    $word_with_spaces = /[a-z]{4,16} [a-z]{2,16} [a-z]{4,16}/ fullword

  condition:
    filesize < 30KB and $gcc_v4 and $fork in (1000..3000) and none of ($not*) and #word_with_spaces < 15
}

private rule binary {
  condition:
    // matches ELF or machO binary
    filesize < 40MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

rule multiple_gcc: medium {
  meta:
    description = "built with multiple versions of GCC"
    filetypes   = "elf,macho"

  strings:
    $gcc = /GCC: \([\w \.\-\~\(\)]{8,64}/ fullword

  condition:
    binary and #gcc > 1 and !gcc[1] != !gcc[2]
}

rule multiple_gcc_high: high {
  meta:
    description = "built with multiple versions of GCC"
    filetypes   = "elf,macho"

  strings:
    $gcc                        = /GCC: \([\w \.\-\~\(\)]{8,64}/ fullword
    $not_go_testdata_ranges_elf = "/home/iant/foo4.c"
    $not_go_testdata            = "dwarf/testdata"
    $not_java                   = "JAVA_HOME"

  condition:
    binary and #gcc > 1 and !gcc[1] != !gcc[2] and none of ($not*)
}
