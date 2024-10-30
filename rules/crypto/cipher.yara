rule go_cipher: harmless {
  meta:
    description = "Uses crypto/cipher"

  strings:
    $ref = "XORKeyStream"

  condition:
    any of them
}
