rule chrome_cookies: high {
  meta:
    ref         = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description = "access Google Chrome Cookie files"

  strings:
    $ref  = "/Google/Chrome"
    $ref2 = "/Cookies"

  condition:
    all of them
}
