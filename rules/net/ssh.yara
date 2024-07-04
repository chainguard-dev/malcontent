
rule ssh : medium {
  meta:
    description = "Uses SSH (secure shell) service"
  strings:
    $ = "SSH" fullword
  condition:
    any of them
}



rule crypto_ssh : medium {
  meta:
    description = "Uses crypto/ssh to connect to the SSH (secure shell) service"
    hash_2024_Downloads_e100 = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"
    hash_2024_Downloads_e241 = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"
    hash_2020_IPStorm_IPStorm_unpacked = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"
  strings:
    $go = "crypto/ssh" fullword
  condition:
    any of them
}
