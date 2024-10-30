rule security: override macos {
  meta:
    description            = "security"
    security_dump_keychain = "medium"

  strings:
    $ref = "@(#)PROGRAM:security"

  condition:
    filesize > 200KB and filesize < 800KB and any of them
}
