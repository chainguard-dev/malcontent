rule openssl_user: medium {
  meta:
    description = "Uses OpenSSL"

  strings:
    $ref  = "_EXT_FLAG_SENT"
    $ref2 = "OpenSSL" fullword
    $ref3 = "openssl" fullword

  condition:
    any of them
}
