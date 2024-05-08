
rule wolfssl : medium {
  meta:
    description = "This binary includes WolfSSL"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2020_Dacls_SubMenu = "846d8647d27a0d729df40b13a644f3bffdc95f6d0e600f2195c85628d59f1dc6"
    hash_2020_Base_lproj_SubMenu = "846d8647d27a0d729df40b13a644f3bffdc95f6d0e600f2195c85628d59f1dc6"
  strings:
    $ref = "WolfSSL"
    $ref2 = "WOLFSSL_"
  condition:
    any of them
}
