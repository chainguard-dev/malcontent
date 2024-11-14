rule openssl_user: medium {
  meta:
    description = "Uses OpenSSL"

  strings:
    $ref = "_EXT_FLAG_SENT"

  condition:
    any of them
}
