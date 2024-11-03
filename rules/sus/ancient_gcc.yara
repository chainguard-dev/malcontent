rule archaic_gcc: medium {
  meta:
    description            = "built by an ancient version of GCC"
    hash_2023_BPFDoor_07ec = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
    hash_2023_BPFDoor_2e0a = "2e0aa3da45a0360d051359e1a038beff8551b957698f21756cfc6ed5539e4bdb"
    hash_2023_BPFDoor_3743 = "3743821d55513c52a9f06d3f6603afd167105a871e410c35a3b94e34c51089e6"

  strings:
    $gcc_v4   = /GCC: \([\w \.\-\~]{1,128}\) 4\.\d{1,16}\.\d{1,128}/
    $not_nacl = "NACLVERBOSITY"

  condition:
    $gcc_v4 and none of ($not*)
}

rule small_opaque_archaic_gcc: high linux {
  meta:
    description = "small and built by an ancient version of GCC"

  strings:
    $gcc_v4           = /GCC: \([\w \.\-\~]{1,128}\) 4\.\d{1,16}\.\d{1,128}/
    $fork             = "fork"
    $not_nacl         = "NACLVERBOSITY"
    $not_usage        = "usage" fullword
    $not_Usage        = "Usage" fullword
    $word_with_spaces = /[a-z]{4,} [a-z]{2,} [a-z]{4,}/

  condition:
    filesize < 30KB and $gcc_v4 and $fork in (1000..3000) and none of ($not*) and #word_with_spaces < 15
}
