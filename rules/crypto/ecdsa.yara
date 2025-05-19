rule crypto_ecdsa {
  meta:
    description = "Uses the Go crypto/ecdsa library"
    filetypes   = "elf,go,macho"

  strings:
    $ref = "crypto/ecdsa"

  condition:
    $ref
}
