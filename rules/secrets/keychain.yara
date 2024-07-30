
rule keychain : medium macos {
  meta:
    description = "May access the macOS keychain"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
  strings:
    $ref = "Keychain"
    $ref2 = "keychain"
    $not_elastic_author = { 22 61 75 74 68 6F 72 22 3A 20 5B 0A 20 20 20 20 22 45 6C 61 73 74 69 63 22 0A 20 20 5D }
    $not_elastic_license = "\"license\": \"Elastic License v2\""
  condition:
    any of ($ref*) and none of ($not*)
}

rule macos_library_keychains : medium {
  meta:
    description = "access system keychain via files"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
  strings:
    $ref = "/Library/Keychains"
    $not_elastic_author = { 22 61 75 74 68 6F 72 22 3A 20 5B 0A 20 20 20 20 22 45 6C 61 73 74 69 63 22 0A 20 20 5D }
    $not_elastic_license = "\"license\": \"Elastic License v2\""
  condition:
    $ref and none of ($not*)
}

rule find_generic_password : high {
  meta:
    description = "Looks up a password from the Keychain"
  strings:
    $ref = /find-generic-passsword[ \-\w\']{0,32}/
    $not_ctkcard = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
    $not_elastic_author = { 22 61 75 74 68 6F 72 22 3A 20 5B 0A 20 20 20 20 22 45 6C 61 73 74 69 63 22 0A 20 20 5D }
    $not_elastic_license = "\"license\": \"Elastic License v2\""
  condition:
    $ref and none of ($not*)
}

rule find_internet_password : high {
  meta:
    description = "Looks up an internet password from the Keychain"
  strings:
    $ref = /find-internet-passsword[ \-\w\']{0,32}/
    $not_ctkcard = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
    $not_elastic_author = { 22 61 75 74 68 6F 72 22 3A 20 5B 0A 20 20 20 20 22 45 6C 61 73 74 69 63 22 0A 20 20 5D }
    $not_elastic_license = "\"license\": \"Elastic License v2\""
  condition:
    $ref and none of ($not*)
}
