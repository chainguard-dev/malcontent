rule XProtectMention: medium {
  meta:
    hash_2023_JokerSpy_xcc = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"

  strings:
    $xprotect    = "XProtect"
    $not_apple   = "com.apple.private"
    $not_osquery = "OSQUERY_WORKER"
    $not_kandji  = "com.kandji.profile.mdmprofile"

  condition:
    $xprotect and none of ($not*)
}
