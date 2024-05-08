
rule unarchive : medium {
  meta:
    description = "unarchives files"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2023_Linux_Malware_Samples_2f85 = "2f85ca8f89dfb014b03afb11e5d2198a8adbae1da0fd76c81c67a81a80bf1965"
    hash_2023_Linux_Malware_Samples_5c03 = "5c03ff30ccffc9d36c342510c7469682d3c411654ec52b0930d37a6c6aab9f72"
  strings:
    $ref = /unarchive[\w \@\%]{0,32}/
    $ref2 = /Unarchive[\w \@\%]{0,32}/
  condition:
    any of them
}
