rule http_dynamic: medium {
  meta:
    description              = "URL that is dynamically generated"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"

  strings:
    $ref  = /https*:\/\/%s[\/\w\.]{0,64}/
    $ref2 = "https://%@:%@%@"

  condition:
    any of them
}
