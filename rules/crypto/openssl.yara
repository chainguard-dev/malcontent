rule openssl_user: medium {
  meta:
    description              = "Uses OpenSSL"
    hash_2024_Downloads_ad5b = "ad5b99bbcb9efe65a47d250497eb5d88d28a53ad0dc5d8989f3da4504b4c00f8"

  strings:
    $ref = "_EXT_FLAG_SENT"

  condition:
    any of them
}
