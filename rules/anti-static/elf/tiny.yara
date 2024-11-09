import "elf"

rule impossibly_small_elf_program: high {
  meta:
    description = "ELF binary is unusually small"

  condition:
    filesize < 8192 and uint32(0) == 1179403647 and elf.type == elf.ET_EXEC
}