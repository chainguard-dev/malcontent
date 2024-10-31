import "elf"

rule impossibly_small_elf_program : high {
  meta:
    description = "ELF binary is unusually small"
  condition:
    filesize < 8192 and uint32(0) == 1179403647 and elf.type == elf.ET_EXEC
}

rule impossibly_small_macho_program : medium {
  meta:
    description = "machO binary is unusually small"
  strings:
    $not_jar = "META-INF/"
    $not_dwarf = "_DWARF"
    $not_kext = "_.SYMDEF SORTED"
  condition:
    filesize < 16384 and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178) and none of ($not*)
}
