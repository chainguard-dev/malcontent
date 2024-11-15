rule firefox_cookies: high {
  meta:
    description = "access Firefox cookies"

  strings:
    $firefox      = "Firefox"
    $fcookie      = "cookies.sqlite"
    $not_chromium = "CHROMIUM_TIMESTAMP"

  condition:
    filesize < 100MB and all of ($f*) and none of ($not*)
}
