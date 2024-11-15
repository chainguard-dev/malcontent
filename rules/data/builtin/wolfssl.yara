rule wolfssl: medium {
  meta:
    description = "This binary includes WolfSSL"

  strings:
    $ref  = "WolfSSL"
    $ref2 = "WOLFSSL_"

  condition:
    any of them
}
