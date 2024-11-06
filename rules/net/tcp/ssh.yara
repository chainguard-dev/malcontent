rule ssh: medium {
  meta:
    description                      = "Uses SSH (secure shell) service"
    hash_2024_2022_Conti_8b57e96_elf = "8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201"
    hash_2024_2022_Conti_bb64b27     = "bb64b27bff106d30a7b74b3589cc081c345a2b485a831d7e8c8837af3f238e1e"
    hash_1985_deploy                 = "8729e61daf18a196f7571fa097be32dd7b4dbcc3e3794be1102aa2ad91f4cbe0"

  strings:
    $ = "SSH" fullword
    $ = "ssh_packet" fullword

  condition:
    any of them
}

rule crypto_ssh: medium {
  meta:
    description                        = "Uses crypto/ssh to connect to the SSH (secure shell) service"
    hash_2024_Downloads_e100           = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"
    hash_2024_Downloads_e241           = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"
    hash_2020_IPStorm_IPStorm_unpacked = "522a5015d4d11833ead6d88d4405c0f4119ff29b1f64b226c464e958f03e1434"

  strings:
    $go = "crypto/ssh" fullword

  condition:
    any of them
}
