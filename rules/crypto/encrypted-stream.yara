rule go_encrypted_stream: high {
  meta:
    description = "Uses github.com/nknorg/encrypted-stream to encrypt streams"

  strings:
    $ref1 = ").Encrypt"
    $ref2 = ").Decrypt"
    $ref3 = ").MaxOverhead"
    $ref4 = ").NonceSize"

  condition:
    all of them
}
