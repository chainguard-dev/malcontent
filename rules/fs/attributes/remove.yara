
rule remove_xattr : notable {
  meta:
    description = "remove an extended file attribute value"
    ref = "https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/removexattr.2.html"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"
  strings:
    $ref = "removexattr" fullword
  condition:
    any of them
}
