import "math"

private rule normal_elf {
  condition:
    filesize < 64MB and uint32(0) == 1179403647
}

private rule small_elf {
  condition:
    filesize < 400KB and uint32(0) == 1179403647
}

rule higher_elf_entropy_68: medium {
  meta:
    description = "higher entropy ELF binary (>6.95)"
    filetypes   = "elf"

  condition:
    normal_elf and math.entropy(1, filesize) >= 6.95
}

rule normal_elf_high_entropy_7_4: high {
  meta:
    description = "high entropy ELF binary (>7.4)"
    filetypes   = "elf"

  strings:
    $not_whirlpool = "libgcrypt-grub/cipher/whirlpool.c"
    $not_bazel     = "BazelLogHandler"

  condition:
    filesize < 30MB and normal_elf and math.entropy(1, filesize) >= 7.4 and none of ($not*)
}

rule normal_elf_high_entropy_footer_7_4: high {
  meta:
    description = "high entropy footer in ELF binary (>7.4)"
    filetypes   = "elf"

  condition:
    normal_elf and math.entropy(filesize - 8192, filesize) >= 7.4
}

rule normal_elf_high_entropy_footer_7_4_rc4: high {
  meta:
    description = "high entropy footer in ELF binary (>7.4), likely RC4 encrypted"
    filetypes   = "elf"

  strings:
    $cmp_e_x_256 = { 81 f? 00 01 00 00 }  // cmp {ebx, ecx, edx}, 256
    $cmp_r_x_256 = { 48 81 f? 00 01 00 00 }  // cmp {rbx, rcx, …}, 256

  condition:
    filesize < 25MB and normal_elf and math.entropy(filesize - 8192, filesize) >= 7.4 and any of them
}
