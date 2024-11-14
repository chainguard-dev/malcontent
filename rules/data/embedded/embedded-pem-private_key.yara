rule begin_private_key: medium {
  meta:
    description = "Contains PRIVATE KEY directive"

  strings:
    $ref = "PRIVATE KEY-----"

  condition:
    any of them
}

rule rsa_private_key: medium {
  meta:
    description = "Contains RSA PRIVATE KEY directive"

  strings:
    $ref = "RSA PRIVATE KEY-----"

  condition:
    any of them
}
