import "elf"

rule openssl: medium {
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
