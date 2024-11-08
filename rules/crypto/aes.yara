rule crypto_aes {
  meta:
    description = "Supports AES (Advanced Encryption Standard)"

  strings:
    $ref  = "crypto/aes"
    $ref2 = "AES" fullword
    $ref3 = "openssl/aes"
    $ref4 = "aes_256_cbc"
    $ref5 = "aes_encrypt"

  condition:
    any of them
}
