rule go_cipher: harmless {
  meta:
    description = "Uses crypto/cipher"

  strings:
    $ref = "XORKeyStream"

  condition:
    any of them
}

rule ciphertext: medium {
  meta:
    description = "mentions 'ciphertext'"

  strings:
    $ref = "ciphertext"

  condition:
    any of them
}
