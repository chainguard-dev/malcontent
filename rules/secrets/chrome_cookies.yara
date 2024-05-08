
rule chrome_cookies : high {
  meta:
    ref = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description = "access Google Chrome Cookie files"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2018_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
  strings:
    $ref = "/Google/Chrome"
    $ref2 = "/Cookies"
  condition:
    all of them
}
