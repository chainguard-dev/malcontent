rule security_dump_keychain: critical {
  meta:
    hash_2011_bin_kd = "8eb5ab5d71c84c9927b420948abedcf510369c8d566ee94c0cb5bc276d0d0a72"

  strings:
    $dump                = "dump-keychain"
    $not_ctkcard         = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
    $not_elastic_author  = { 22 61 75 74 68 6F 72 22 3A 20 5B 0A 20 20 20 20 22 45 6C 61 73 74 69 63 22 0A 20 20 5D }
    $not_elastic_license = "\"license\": \"Elastic License v2\""

  condition:
    $dump and none of ($not*)
}
