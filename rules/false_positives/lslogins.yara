rule lastlogins: override linux {
  meta:
    description   = "lastlogins"
    login_records = "low"

  strings:
    $lastlogin = "LAST-LOGIN"
    $max       = "LASTLOG_UID_MAX"

  condition:
    filesize < 100KB and uint32(0) == 1179403647 and any of them
}
