rule built_by_archaic_gcc_version: medium {
  meta:
    hash_2023_BPFDoor_07ec = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
    hash_2023_BPFDoor_2e0a = "2e0aa3da45a0360d051359e1a038beff8551b957698f21756cfc6ed5539e4bdb"
    hash_2023_BPFDoor_3743 = "3743821d55513c52a9f06d3f6603afd167105a871e410c35a3b94e34c51089e6"

  strings:
    $gcc_v4   = /GCC: \([\w \.\-\~]{1,128}\) 4\.\d{1,16}\.\d{1,128}/
    $not_nacl = "NACLVERBOSITY"

  condition:
    $gcc_v4 and none of ($not*)
}
