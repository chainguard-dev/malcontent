rule password_finder_generic: high {
  meta:
    description                = "password finder or dumper"
    hash_2024_hCrypto_main_en  = "4d4d52eed849554e1c31d56239bcf8ddc7e27fd387330f5ab1ce7d118589e5f3"
    hash_2024_hCrypto_main_ru  = "ab531d7eb4160bdf1ef5c3e745ad92601f66afa13c150b2547cbe788db84d7d1"
    hash_2024_dumpcreds_3snake = "6f2ec2921dd8da2a9bbc4ca51060b2c5f623b0e8dc904e23e27b9574f991848b"

  strings:
    $ref  = "findPassword"
    $ref2 = "find_password"

  condition:
    filesize < 25MB and any of them
}

rule gnome_keyring_sync: override {
  meta:
    description             = "looks up passwords via gnome_keyring"
    password_finder_generic = "medium"

  strings:
    $ref = "gnome_keyring_find_password_sync"

  condition:
    filesize > 5MB and any of them
}

rule password_dumper_generic: high {
  meta:
    description                     = "password dumper"
    hash_2024_dumpcreds_mimipenguin = "79b478d9453cb18d2baf4387b65dc01b6a4f66a620fa6348fa8dbb8549a04a20"

  strings:
    $ref3 = "dumpPassword"
    $ref4 = "dump_password"

  condition:
    any of them
}
