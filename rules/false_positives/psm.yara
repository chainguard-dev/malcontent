rule psm: override macos {
  meta:
    description   = "psm"
    macos_cookies = "medium"

  strings:
    $ref = "com.apple.psm" fullword

  condition:
    filesize < 400KB and filesize > 40KB and any of them
}
