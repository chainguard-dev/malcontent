rule begin_cert {
  meta:
    description = "Contains embedded PEM certificate"

  strings:
    $ref = "-----BEGIN CERTIFICATE-----"

  condition:
    any of them
}

