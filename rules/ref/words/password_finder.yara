
rule password_finder_generic : suspicious {
  meta:
    description = "password finder or dumper"
    hash_2024_hCrypto_main_en = "4d4d52eed849554e1c31d56239bcf8ddc7e27fd387330f5ab1ce7d118589e5f3"
    hash_2024_hCrypto_main_ru = "ab531d7eb4160bdf1ef5c3e745ad92601f66afa13c150b2547cbe788db84d7d1"
  strings:
    $ref = "findPassword"
    $ref2 = "find_password"
  condition:
    any of them
}

rule password_dumper_generic : suspicious {
  meta:
    description = "password dumper"
  strings:
    $ref3 = "dumpPassword"
    $ref4 = "dump_password"
  condition:
    any of them
}
