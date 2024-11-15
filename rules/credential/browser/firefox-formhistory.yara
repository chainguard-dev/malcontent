rule firefox_history: high {
  meta:
    description = "access Firefox form history, which contains passwords"

  strings:
    $firefox      = "Firefox"
    $formhist     = "formhistory.sqlite"
    $not_chromium = "CHROMIUM_TIMESTAMP"

  condition:
    filesize < 100MB and all of ($f*) and none of ($not*)
}
