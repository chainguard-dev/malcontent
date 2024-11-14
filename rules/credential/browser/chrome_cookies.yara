rule chrome_cookies: high {
  meta:
    ref                      = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description              = "access Google Chrome Cookie files"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2018_Calisto        = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"

  strings:
    $ref  = "/Google/Chrome"
    $ref2 = "/Cookies"

  condition:
    all of them
}
