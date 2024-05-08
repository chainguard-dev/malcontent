
rule keychain : medium macos {
  meta:
    description = "May access the macOS keychain"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
  strings:
    $ref = "Keychain"
    $ref2 = "keychain"
  condition:
    any of them
}

rule macos_library_keychains : medium {
  meta:
    description = "access system keychain via files"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
  strings:
    $ref = "/Library/Keychains"
  condition:
    any of them
}

rule find_generic_password : high {
  meta:
    description = "Looks up a password from the Keychain"
  strings:
    $ref = /find-generic-passsword[ \-\w\']{0,32}/
    $ctkcard = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
  condition:
    $ref and not $ctkcard
}

rule find_internet_password : high {
  meta:
    description = "Looks up an internet password from the Keychain"
  strings:
    $ref = /find-internet-passsword[ \-\w\']{0,32}/
    $ctkcard = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
  condition:
    $ref and not $ctkcard
}
