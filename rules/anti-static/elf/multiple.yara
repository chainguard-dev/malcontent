import "elf"

rule multiple_elf: medium {
  meta:
    description = "multiple ELF binaries within an ELF binary"
    filetypes   = "elf"

  strings:
    $elf_head = "\x7fELF"

  condition:
    uint32(0) == 1179403647 and #elf_head > 1
}
