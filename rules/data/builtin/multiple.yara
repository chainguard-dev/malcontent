include "rules/global.yara"

import "elf"

rule elf_with_bundled_glibc_and_openssl: high {
  meta:
    description = "includes bundled copy of glibc and OpenSSL"
    filetypes   = "elf"

  condition:
    bundled_openssl and bundled_glibc
}
