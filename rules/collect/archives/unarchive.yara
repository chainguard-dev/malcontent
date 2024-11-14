rule unarchive: medium {
  meta:
    description              = "unarchives files"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"

  strings:
    $ref  = /unarchive[\w \@\%]{0,32}/
    $ref2 = /Unarchive[\w \@\%]{0,32}/

  condition:
    any of them
}
