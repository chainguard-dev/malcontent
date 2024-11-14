import "elf"

rule elf_with_bundled_glibc: medium {
  meta:
    description = "includes bundled copy of glibc"

  strings:
    $glibc_private  = "GLIBC_PRIVATE"
    $glibc_tunables = "GLIBC_TUNABLES"
    $setup_vdso     = "setup_vdso"

  condition:
    filesize > 1024 and filesize < 25MB and elf.type == elf.ET_EXEC and uint32(0) == 1179403647 and all of them
}
