
rule security_dump_keychain : critical {
  meta:
    hash_2011_Twitterrific_bin_bop = "d2398b764758e23fcac6e29358f36d79e32cdea05c99d95e8423fb0c6943a291"
    hash_2011_bin_kd = "8eb5ab5d71c84c9927b420948abedcf510369c8d566ee94c0cb5bc276d0d0a72"
  strings:
    $dump = "dump-keychain"
    $ctkcard = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
  condition:
    $dump and not $ctkcard
}

