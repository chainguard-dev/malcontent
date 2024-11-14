rule cryptonight: high {
  meta:
    description = "References CryptoNight, a proof-of-work algorithm"


    hash_2023_usr_adxintrin_b  = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"

  strings:
    $ref  = "cryptonight"
    $ref2 = "Cryptonight"

  condition:
    any of them
}
