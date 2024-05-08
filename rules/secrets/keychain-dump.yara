
rule security_dump_keychain : critical {
  strings:
    $dump = "dump-keychain"
    $ctkcard = "/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard"
  condition:
    $dump and not $ctkcard
}
