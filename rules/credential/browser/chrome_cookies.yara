rule chrome_cookies: high {
  meta:
    ref         = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description = "access Google Chrome Cookie files"

    hash_2018_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"

  strings:
    $ref  = "/Google/Chrome"
    $ref2 = "/Cookies"

  condition:
    all of them
}
