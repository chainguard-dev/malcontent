import "elf"

rule contains_base64_elf: high {
  meta:
    description = "contains base64 ELF binary"

  strings:
    $elf_head = "f0VMRgI"

  condition:
    any of them
}

rule elf_contains_base64_elf: critical {
  meta:
    description = "ELF binary contains base64 ELF binary"
    filetypes   = "elf"

  strings:
    $elf_head = "f0VMRgI"

  condition:
    uint32(0) == 1179403647 and any of them
}
