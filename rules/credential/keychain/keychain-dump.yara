rule security_dump_keychain: critical {
  meta:
    description = "dumps keychain contents"

  strings:
    $dump                = "dump-keychain"
    $not_ctkcard         = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
    $not_elastic_author  = "\"author\": [\n    \"Elastic\"\n  ]"
    $not_elastic_license = "\"license\": \"Elastic License v2\""

  condition:
    $dump and none of ($not*)
}
