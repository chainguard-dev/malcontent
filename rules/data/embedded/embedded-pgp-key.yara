rule begin_pgp_public_key {
  meta:
    description = "Contains embedded PEM certificate"

  strings:
    $ref = "-----BEGIN PGP PUBLIC KEY BLOCK-----"

  condition:
    any of them
}
