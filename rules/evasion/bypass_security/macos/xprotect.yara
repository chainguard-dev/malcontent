rule XProtectMention: medium {
  meta:
    description = "mentions 'XProtect'"

  strings:
    $xprotect    = "XProtect"
    $not_apple   = "com.apple.private"
    $not_osquery = "OSQUERY_WORKER"
    $not_kandji  = "com.kandji.profile.mdmprofile"

  condition:
    $xprotect and none of ($not*)
}
