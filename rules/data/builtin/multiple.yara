import "elf"

include "rules/global/global.yara"

rule elf_with_bundled_glibc_and_openssl: high {
  meta:
    description = "includes bundled copy of glibc and OpenSSL"
    filetypes   = "elf"

  condition:
    global_bundled_openssl and global_bundled_glibc
}
