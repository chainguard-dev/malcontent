rule impossibly_small_macho_program: medium {
  meta:
    description = "machO binary is unusually small"
    filetypes   = "macho"

  strings:
    $stub_helper = "__stub_helper"

  condition:
    filesize < 16384 and (uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca) and $stub_helper
}
