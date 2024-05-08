
rule http_dynamic : notable {
  meta:
    description = "URL that is dynamically generated"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2023_Linux_Malware_Samples_1b1a = "1b1a56aec5b02355b90f911cdd27a35d099690fcbeb0e0622eaea831d64014d3"
  strings:
    $ref = /https*:\/\/%s[\/\w\.]{0,64}/
    $ref2 = "https://%@:%@%@"
  condition:
    any of them
}
