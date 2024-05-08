
rule nicehash_pool : suspicious {
  meta:
    description = "References Nicehash and mining pools"
    hash_2023_Multios_Coinminer_Miner_6f28 = "6f2825856a5ae87face1c68ccb7f56f726073b8639a0897de77da25c8ecbeb19"
    hash_2023_gcclib_xfitaarch = "163f78541c2fbdad128997534ecc2ad31b112f779347c526dd4e071a608de85c"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
  strings:
    $ref = "nicehash"
    $ref2 = "pool"
  condition:
    all of them
}
