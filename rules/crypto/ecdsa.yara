rule crypto_ecdsa {
  meta:
    description = "Uses the Go crypto/ecdsa library"

  strings:
    $ref = "crypto/ecdsa"

  condition:
    $ref
}
