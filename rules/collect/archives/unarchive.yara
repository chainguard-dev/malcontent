rule unarchive: medium {
  meta:
    description = "unarchives files"

  strings:
    $ref  = /unarchive[\w \@\%]{0,32}/
    $ref2 = /Unarchive[\w \@\%]{0,32}/

  condition:
    any of them
}
