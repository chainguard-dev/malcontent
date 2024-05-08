
rule go_encrypted_stream : suspicious {
  meta:
    description = "Uses github.com/nknorg/encrypted-stream to encrypt streams"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
  strings:
    $ref1 = ").Encrypt"
    $ref2 = ").Decrypt"
    $ref3 = ").MaxOverhead"
    $ref4 = ").NonceSize"
  condition:
    all of them
}
