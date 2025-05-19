import "elf"

rule impossibly_small_elf_program: high {
  meta:
    description = "ELF binary is unusually small"
    filetypes   = "elf"

  strings:
    $not_hello_c = "hello.c"

  condition:
    filesize < 8192 and filesize > 900 and uint32(0) == 1179403647 and elf.type == elf.ET_EXEC and none of ($not*)
}
