import "elf"

private rule _bundled_openssl: medium {
  meta:
    description = "includes bundled copy of OpenSSL"

  strings:
    $ref        = "OpenSSL/"
    $aes_part   = "AES part of OpenSSL"
    $montgomery = "Montgomery Multiplication for x86_64, CRYPTOGAMS"
    $rc4        = "RC4 for x86_64, CRYPTOGAMS"

  condition:
    filesize > 1024 and filesize < 150MB and elf.type == elf.ET_EXEC and uint32(0) == 1179403647 and any of them
}

private rule _bundled_glibc: medium {
  meta:
    description = "includes bundled copy of glibc"

  strings:
    $glibc_private  = "GLIBC_PRIVATE"
    $glibc_tunables = "GLIBC_TUNABLES"
    $setup_vdso     = "setup_vdso"

  condition:
    filesize > 1024 and filesize < 25MB and elf.type == elf.ET_EXEC and uint32(0) == 1179403647 and all of them
}

rule elf_with_bundled_glibc_and_openssl: high {
  meta:
    description = "includes bundled copy of glibc and OpenSSL"
    filetypes   = "elf"

  condition:
    _bundled_openssl and _bundled_glibc
}
