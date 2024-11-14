rule nicehash_pool: high {
  meta:
    description = "References Nicehash and mining pools"

    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"

  strings:
    $ref  = "nicehash"
    $ref2 = "pool"

  condition:
    all of them
}
