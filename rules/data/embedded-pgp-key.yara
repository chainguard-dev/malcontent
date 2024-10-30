rule begin_cert {
  meta:
    description = "Contains embedded PEM certificate"

  strings:
    $ref = "-----BEGIN PGP PUBLIC KEY BLOCK-----"

  condition:
    any of them
}
