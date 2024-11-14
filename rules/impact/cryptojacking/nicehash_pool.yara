rule nicehash_pool: high {
  meta:
    description = "References Nicehash and mining pools"

    hash_2023_gcclib_xfitaarch = "163f78541c2fbdad128997534ecc2ad31b112f779347c526dd4e071a608de85c"
    hash_2023_usr_adxintrin_b  = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"

  strings:
    $ref  = "nicehash"
    $ref2 = "pool"

  condition:
    all of them
}
