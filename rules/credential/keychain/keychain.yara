rule keychain: medium macos {
  meta:
    description = "accesses a keychain"

  strings:
    $ref                 = "Keychain"
    $ref2                = "keychain"
    $not_elastic_author  = "\"author\": [\n    \"Elastic\"\n  ]"
    $not_elastic_license = "\"license\": \"Elastic License v2\""

  condition:
    any of ($ref*) and none of ($not*)
}

rule macos_library_keychains: medium macos {
  meta:
    description = "access system keychain via files"

  strings:
    $ref                 = "/Library/Keychains"
    $not_elastic_author  = "\"author\": [\n    \"Elastic\"\n  ]"
    $not_elastic_license = "\"license\": \"Elastic License v2\""

  condition:
    $ref and none of ($not*)
}

rule find_generic_password: high macos {
  meta:
    description = "Looks up a password from the Keychain"

  strings:
    $ref                 = /find-generic-passsword[ \-\w\']{0,32}/
    $not_ctkcard         = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
    $not_elastic_author  = "\"author\": [\n    \"Elastic\"\n  ]"
    $not_elastic_license = "\"license\": \"Elastic License v2\""

  condition:
    $ref and none of ($not*)
}

rule find_internet_password: high macos {
  meta:
    description = "Looks up an internet password from the Keychain"

  strings:
    $ref                 = /find-internet-passsword[ \-\w\']{0,32}/
    $not_ctkcard         = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
    $not_elastic_author  = "\"author\": [\n    \"Elastic\"\n  ]"
    $not_elastic_license = "\"license\": \"Elastic License v2\""

  condition:
    $ref and none of ($not*)
}

rule login_keychain: high macos {
  meta:
    description = "may steal login keychain"

  strings:
    $ref = "/Library/Keychains/login.keychain-db"

  condition:
    filesize < 200MB and $ref
}

rule adobe_sam_login_keychain: override macos {
  meta:
    description    = "Adobe SAM"
    login_keychain = "medium"

  strings:
    $ref = "com.adobe.acc.sam-v2.dylib"

  condition:
    filesize > 50MB and filesize < 100MB and $ref
}

rule login_keychain_eager_beaver: critical macos {
  meta:
    description = "steals login keychain"
    ref         = "https://www.group-ib.com/blog/apt-lazarus-python-scripts/"

  strings:
    $ref  = "logkc_db" fullword
    $ref2 = "Keychains" fullword

  condition:
    filesize < 200MB and all of them
}
