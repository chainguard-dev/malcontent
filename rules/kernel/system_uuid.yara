
rule macos_platform_check : notable {
  meta:
    description = "machine unique identifier"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
  strings:
    $ref = "IOPlatformUUID" fullword
    $ref2 = "DeviceIDInKeychain"
  condition:
    any of them
}
