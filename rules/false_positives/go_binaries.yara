// Kobalos and TSCookie are small C implants. Their third-party rules fire on any
// one 4-7 byte pattern (an RSA-512 modulus header, two command opcodes), which
// recur by chance in the machine code and pclntab of large Go binaries.
rule go_binary_short_byte_patterns: override {
  meta:
    description                        = "large Go ELF binary"
    ESET_Kobalos                       = "low"
    SIGNATURE_BASE_APT_MAL_LNX_Kobalos = "low"
    BlackTech_TSCookie_elf             = "low"

  strings:
    $go_buildinfo = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }

  condition:
    uint32(0) == 0x464c457f and filesize > 20MB and $go_buildinfo
}
