import "math"

private rule normal_elf {
  condition:
    filesize < 64MB and uint32(0) == 1179403647
}

private rule small_elf {
  condition:
    filesize < 400KB and uint32(0) == 1179403647
}

rule normal_elf_high_entropy_7: medium {
  meta:
    description = "higher entropy ELF binary (>7.1)"

  condition:
    normal_elf and math.entropy(1, filesize) >= 7.1
}

rule normal_elf_high_entropy_7_4: high {
  meta:
    description = "high entropy ELF binary (>7.4)"

  strings:
    $not_whirlpool = "libgcrypt-grub/cipher/whirlpool.c"

  condition:
    normal_elf and math.entropy(1, filesize) >= 7.4 and none of ($not*)
}
