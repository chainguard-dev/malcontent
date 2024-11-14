rule begin_private_key: medium {
  meta:
    description              = "Contains PRIVATE KEY directive"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"

  strings:
    $ref = "PRIVATE KEY-----"

  condition:
    any of them
}

rule rsa_private_key: medium {
  meta:
    description              = "Contains RSA PRIVATE KEY directive"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"

  strings:
    $ref = "RSA PRIVATE KEY-----"

  condition:
    any of them
}
